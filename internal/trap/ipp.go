package trap

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

const (
	// ippMaxAttrs bounds the attributes inspected in one request.
	ippMaxAttrs = 64
	// ippMaxNameLen bounds an attribute name; IPP allows 255 bytes.
	ippMaxNameLen = 255
	// ippMaxJobName bounds the job name kept for logs and meta.
	ippMaxJobName = 64

	ippOpPrintJob         = 0x0002
	ippOpValidateJob      = 0x0004
	ippOpCreateJob        = 0x0005
	ippOpSendDocument     = 0x0006
	ippOpSendURI          = 0x0007
	ippOpCancelJob        = 0x0008
	ippOpGetJobAttributes = 0x0009
	ippOpGetJobs          = 0x000A
	ippOpGetPrinterAttrs  = 0x000B
	ippOpCUPSGetDefault   = 0x4001
	ippOpCUPSGetPrinters  = 0x4002

	ippStatusOK                    = 0x0000
	ippStatusNotAuthorized         = 0x0403
	ippStatusNotFound              = 0x0406
	ippStatusOperationNotSupp      = 0x0501
	ippKindAttributes              = "attributes"
	ippKindPrintJob                = "print_job"
	ippKindOther                   = "other"
	ippPrinterState                = 3 // idle
	ippServerHeader                = "CUPS/2.4 IPP/2.1"
	ippHomePage                    = "<!DOCTYPE html>\n<html><head><title>Home - CUPS 2.4</title></head><body><h1>CUPS 2.4</h1><p>Printing system</p></body></html>\n"
	ippBadRequestBody              = "Bad Request\n"
	ippPrinterURI                  = "ipp://localhost/ipp/print"
	ippPrinterName                 = "HP-LaserJet-M605dn"
	ippPrinterModel                = "HP LaserJet M605dn"
	ippPrinterInfo                 = "HP LaserJet M605dn"
	ippTagOperationAttrs      byte = 0x01
	ippTagEnd                 byte = 0x03
	ippTagPrinterAttrs        byte = 0x04
)

const (
	// ippMaxDocBytes caps the document size reported in alert meta.
	ippMaxDocBytes int64 = 1 << 31
	// ippPrinterUpTime is the static printer-up-time value.
	ippPrinterUpTime = 1893021
)

// IPPTrap is a stub of an IPP printer (CUPS style). It reuses the HTTP trap for
// listening, per-connection sessions, limits and shutdown, and only swaps the
// request handler. Printer attributes are fixed; nothing in the response comes
// from the request except the version family and the request id.
type IPPTrap struct {
	*HTTPTrap
}

func NewIPP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *IPPTrap {
	t := &IPPTrap{HTTPTrap: newHTTPTrap("ipp", cfg, logger, m, limiter, alerter)}
	t.setHandler(t.handle)
	return t
}

var errIPPMalformed = errors.New("ipp: malformed request")

// ippRequest is what the trap decodes from an IPP request body.
type ippRequest struct {
	major, minor byte
	operation    uint16
	requestID    uint32
	jobName      string
	// docOffset is the index of the first document byte (after the
	// end-of-attributes tag), or -1 when there is none.
	docOffset int
}

// parseIPP decodes the header and the attribute groups of an IPP request. Every
// read is bounds checked, names are capped at ippMaxNameLen, at most ippMaxAttrs
// attributes are inspected and nothing is allocated from a decoded length. Only
// the job name is kept, cut to ippMaxJobName bytes.
func parseIPP(b []byte) (ippRequest, error) {
	req := ippRequest{docOffset: -1}
	if len(b) < 9 {
		return req, errIPPMalformed
	}
	req.major, req.minor = b[0], b[1]
	if (req.major != 1 || req.minor > 1) && (req.major != 2 || req.minor > 2) {
		return req, errIPPMalformed
	}
	req.operation = binary.BigEndian.Uint16(b[2:4])
	req.requestID = binary.BigEndian.Uint32(b[4:8])

	off := 8
	attrs := 0
	lastName := ""
	// Past ippMaxAttrs attributes the values are skipped, not inspected, and a
	// structural error is tolerated; the scan goes on only to find the end tag.
	bad := func() (ippRequest, error) {
		if attrs > ippMaxAttrs {
			return req, nil
		}
		return req, errIPPMalformed
	}
	for off < len(b) {
		tag := b[off]
		off++
		if tag == ippTagEnd {
			// The document starts here; off == len(b) means no document byte is in hand.
			req.docOffset = off
			return req, nil
		}
		if tag < 0x10 {
			// Group delimiter.
			lastName = ""
			continue
		}
		if off+2 > len(b) {
			return bad()
		}
		nl := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		if nl > ippMaxNameLen || off+nl+2 > len(b) {
			return bad()
		}
		name := string(b[off : off+nl])
		off += nl
		vl := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		if off+vl > len(b) {
			return bad()
		}
		val := b[off : off+vl]
		off += vl

		if nl == 0 {
			name = lastName
		} else {
			lastName = name
		}
		if attrs++; attrs <= ippMaxAttrs && name == "job-name" && req.jobName == "" && (tag == 0x41 || tag == 0x42) {
			req.jobName = truncateRunes(strings.ToValidUTF8(string(val[:min(len(val), ippMaxJobName)]), "?"), ippMaxJobName)
		}
	}
	return bad()
}

// ippDocBytes returns the size of the document of a request, at most
// ippMaxDocBytes. The bytes in hand after the end-of-attributes tag are counted;
// when the body was cut at maxHTTPBody the declared Content-Length (clamped first)
// is the better figure. Without an offset (the end tag was not found) it is 0.
// A chunked body has no declared length, so a cut chunked document is
// understated by everything past the cut.
func ippDocBytes(req ippRequest, bodyLen int, truncated bool, contentLength int64) int64 {
	if req.docOffset < 0 {
		return 0
	}
	n := int64(bodyLen - req.docOffset)
	if truncated {
		n = max(n, contentLength-int64(req.docOffset))
	}
	return min(max(n, 0), ippMaxDocBytes)
}

// ippOpName names the operations the trap distinguishes; others get their code.
func ippOpName(op uint16) string {
	switch op {
	case ippOpPrintJob:
		return "Print-Job"
	case ippOpValidateJob:
		return "Validate-Job"
	case ippOpCreateJob:
		return "Create-Job"
	case ippOpSendDocument:
		return "Send-Document"
	case ippOpSendURI:
		return "Send-URI"
	case ippOpCancelJob:
		return "Cancel-Job"
	case ippOpGetJobAttributes:
		return "Get-Job-Attributes"
	case ippOpGetJobs:
		return "Get-Jobs"
	case ippOpGetPrinterAttrs:
		return "Get-Printer-Attributes"
	case ippOpCUPSGetDefault:
		return "CUPS-Get-Default"
	case ippOpCUPSGetPrinters:
		return "CUPS-Get-Printers"
	}
	return "op-0x" + strconv.FormatUint(uint64(op), 16)
}

// ippKindOf classifies an operation: read-only queries (Get-Printer-Attributes,
// Get-Jobs, Get-Job-Attributes, Validate-Job and the CUPS listings) are probes,
// job submission is print_job, everything else is other.
func ippKindOf(op uint16) (kind string, attack bool) {
	switch op {
	case ippOpGetPrinterAttrs, ippOpGetJobs, ippOpGetJobAttributes, ippOpValidateJob, ippOpCUPSGetDefault, ippOpCUPSGetPrinters:
		return ippKindAttributes, false
	case ippOpPrintJob, ippOpCreateJob, ippOpSendDocument, ippOpSendURI:
		return ippKindPrintJob, true
	}
	return ippKindOther, true
}

// ippWriter builds IPP attribute bytes.
type ippWriter struct{ b []byte }

func (w *ippWriter) attr(tag byte, name string, value []byte) {
	w.b = append(w.b, tag)
	w.b = binary.BigEndian.AppendUint16(w.b, uint16(len(name)))
	w.b = append(w.b, name...)
	w.b = binary.BigEndian.AppendUint16(w.b, uint16(len(value)))
	w.b = append(w.b, value...)
}

func (w *ippWriter) str(tag byte, name, value string) { w.attr(tag, name, []byte(value)) }

func (w *ippWriter) integer(tag byte, name string, v uint32) {
	w.attr(tag, name, binary.BigEndian.AppendUint32(nil, v))
}

func (w *ippWriter) boolean(name string, v bool) {
	b := byte(0)
	if v {
		b = 1
	}
	w.attr(0x22, name, []byte{b})
}

// ippOperationAttrs is the operation attributes group every response starts with.
func ippOperationAttrs() []byte {
	w := &ippWriter{b: []byte{ippTagOperationAttrs}}
	w.str(0x47, "attributes-charset", "utf-8")
	w.str(0x48, "attributes-natural-language", "en")
	return w.b
}

// ippPrinterAttrs is the fixed printer attributes group.
func ippPrinterAttrs() []byte {
	w := &ippWriter{b: []byte{ippTagPrinterAttrs}}
	w.str(0x45, "printer-uri-supported", ippPrinterURI)
	w.str(0x44, "uri-security-supported", "none")
	w.str(0x44, "uri-authentication-supported", "none")
	w.str(0x42, "printer-name", ippPrinterName)
	w.str(0x41, "printer-make-and-model", ippPrinterModel)
	w.str(0x41, "printer-info", ippPrinterInfo)
	w.integer(0x23, "printer-state", ippPrinterState)
	w.str(0x44, "printer-state-reasons", "none")
	w.boolean("printer-is-accepting-jobs", true)
	w.str(0x44, "ipp-versions-supported", "1.0")
	for _, v := range []string{"1.1", "2.0", "2.1", "2.2"} {
		w.str(0x44, "", v)
	}
	w.integer(0x21, "printer-up-time", ippPrinterUpTime)
	w.integer(0x23, "operations-supported", ippOpPrintJob)
	for _, op := range []uint32{ippOpValidateJob, ippOpCreateJob, ippOpSendDocument, ippOpCancelJob, ippOpGetJobAttributes, ippOpGetJobs, ippOpGetPrinterAttrs} {
		w.integer(0x23, "", op)
	}
	w.str(0x47, "charset-configured", "utf-8")
	w.str(0x47, "charset-supported", "utf-8")
	w.str(0x48, "natural-language-configured", "en")
	w.str(0x48, "generated-natural-language-supported", "en")
	w.str(0x49, "document-format-default", "application/octet-stream")
	w.str(0x49, "document-format-supported", "application/octet-stream")
	w.str(0x49, "", "application/pdf")
	w.str(0x49, "", "application/postscript")
	w.str(0x44, "compression-supported", "none")
	w.integer(0x21, "queued-job-count", 0)
	w.boolean("color-supported", false)
	w.str(0x44, "pdl-override-supported", "not-attempted")
	return w.b
}

var (
	ippOpAttrsBytes      = ippOperationAttrs()
	ippPrinterAttrsBytes = ippPrinterAttrs()
)

// ippResponse builds an IPP response. The version is the request's own when it is
// 1.x and 2.0 otherwise, the request id is echoed; no other request data is used.
func ippResponse(req ippRequest, status uint16, withPrinter bool) []byte {
	major, minor := byte(2), byte(0)
	if req.major == 1 {
		major, minor = 1, req.minor
	}
	out := []byte{major, minor}
	out = binary.BigEndian.AppendUint16(out, status)
	out = binary.BigEndian.AppendUint32(out, req.requestID)
	out = append(out, ippOpAttrsBytes...)
	if withPrinter {
		out = append(out, ippPrinterAttrsBytes...)
	}
	return append(out, ippTagEnd)
}

func (t *IPPTrap) handle(w http.ResponseWriter, r *http.Request) {
	req, ok := newStubRequest(w, r)
	if !ok {
		return
	}
	sess := req.sess
	h := w.Header()
	h.Set("Server", ippServerHeader)

	if r.Method != http.MethodPost {
		t.handlePlain(w, r, req)
		return
	}

	ipp, err := parseIPP(req.body)
	if err != nil {
		// A POST that is not IPP: record it by method and path, never the body.
		req.command(req.method + " " + req.path)
		req.meta["kind"] = ippKindOther
		sess.Alert(r.Context(), req.meta)
		http.Error(w, strings.TrimSpace(ippBadRequestBody), http.StatusBadRequest)
		return
	}

	kind, attack := ippKindOf(ipp.operation)
	op := ippOpName(ipp.operation)
	docBytes := ippDocBytes(ipp, len(req.body), req.truncated, r.ContentLength)
	attrs := append(req.attrs, slog.String("kind", kind), slog.String("operation", op))

	if attack || req.jndi {
		cmd := "ipp " + op
		if ipp.jobName != "" {
			cmd += " job-name=" + ipp.jobName
		}
		// The alert vocabulary has no "attributes": a JNDI string in a read-only
		// request is reported as other.
		req.meta["kind"] = kind
		if !attack {
			req.meta["kind"] = ippKindOther
		}
		req.meta["operation"] = op
		req.meta["document_bytes"] = strconv.FormatInt(docBytes, 10)
		if ipp.jobName != "" {
			req.meta["job_name"] = metaCommandText(ipp.jobName)
		}
		req.attrs = attrs
		req.command(cmd)
		if docBytes > 0 {
			sess.LogPayloadSize("ipp_document", int(min(docBytes, int64(maxPayloadBytes))), slog.Int64("bytes", docBytes))
		}
		sess.Alert(r.Context(), req.meta)
	} else {
		sess.Log("ipp request", attrs...)
	}

	h.Set("Content-Type", "application/ipp")
	w.WriteHeader(http.StatusOK)
	switch {
	case ipp.operation == ippOpGetJobAttributes:
		// There is no job to describe.
		_, _ = w.Write(ippResponse(ipp, ippStatusNotFound, false))
	case !attack:
		_, _ = w.Write(ippResponse(ipp, ippStatusOK, ipp.operation == ippOpGetPrinterAttrs || ipp.operation == ippOpCUPSGetDefault || ipp.operation == ippOpCUPSGetPrinters))
	case kind == ippKindPrintJob:
		_, _ = w.Write(ippResponse(ipp, ippStatusNotAuthorized, false))
	default:
		_, _ = w.Write(ippResponse(ipp, ippStatusOperationNotSupp, false))
	}
}

// handlePlain serves non-POST requests: read-only methods get a static page and
// stay a probe, anything else is recorded by method and path.
func (t *IPPTrap) handlePlain(w http.ResponseWriter, r *http.Request, req *stubRequest) {
	sess := req.sess
	readOnly := isReadOnlyMethod(r.Method)
	alerted := false
	switch {
	case req.jndi, !readOnly:
		req.command(req.method + " " + req.path)
		alerted = true
	default:
		sess.Log("ipp request", req.attrs...)
	}
	if req.bodyLen > 0 && !alerted {
		sess.LogPayloadSize("http_body", req.bodyLen, slog.String("path", req.path), slog.Int("bytes", req.bodyLen))
		alerted = true
	}
	if alerted {
		req.meta["kind"] = ippKindOther
		sess.Alert(r.Context(), req.meta)
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	switch {
	case !readOnly:
		w.WriteHeader(http.StatusMethodNotAllowed)
	case r.URL.Path == "/" || r.URL.Path == "/ipp/print" || strings.HasPrefix(r.URL.Path, "/printers"):
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(ippHomePage))
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
