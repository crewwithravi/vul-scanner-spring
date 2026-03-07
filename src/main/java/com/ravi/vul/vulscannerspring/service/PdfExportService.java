package com.ravi.vul.vulscannerspring.service;

import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.ast.Node;
import com.vladsch.flexmark.util.data.MutableDataSet;
import org.springframework.stereotype.Service;
import org.xhtmlrenderer.pdf.ITextRenderer;

import java.io.ByteArrayOutputStream;

@Service
public class PdfExportService {

    private final Parser mdParser;
    private final HtmlRenderer htmlRenderer;

    public PdfExportService() {
        MutableDataSet opts = new MutableDataSet();
        mdParser = Parser.builder(opts).build();
        htmlRenderer = HtmlRenderer.builder(opts).build();
    }

    public byte[] generatePdf(String markdownText) throws Exception {
        // Strip the hidden machine-readable allowlist line before rendering
        String cleaned = markdownText.replaceAll("(?m)^Dependency Allowlist:.*$", "").trim();

        // Markdown → HTML
        Node doc = mdParser.parse(cleaned);
        String body = htmlRenderer.render(doc);

        // Sanitise for XHTML: self-close <br>, <hr>, <img>
        body = body.replaceAll("<br>", "<br/>")
                   .replaceAll("<hr>", "<hr/>")
                   .replaceAll("<img([^>]*)>", "<img$1/>");

        String xhtml = buildXhtml(body);

        // HTML → PDF
        ITextRenderer renderer = new ITextRenderer();
        renderer.setDocumentFromString(xhtml);
        renderer.layout();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        renderer.createPDF(out);
        return out.toByteArray();
    }

    private static String buildXhtml(String body) {
        return """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
                "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
            <html xmlns="http://www.w3.org/1999/xhtml">
            <head>
              <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
              <title>VulnHawk Security Report</title>
              <style type="text/css">
                @page { margin: 2cm 2.2cm; }
                body  { font-family: Arial, Helvetica, sans-serif; font-size: 10pt; color: #111827; line-height: 1.5; }
                h1    { font-size: 17pt; color: #b91c1c; margin-top: 0; margin-bottom: 4pt; }
                h2    { font-size: 12pt; color: #1f2937; border-left: 3pt solid #ef4444;
                        padding: 4pt 0 4pt 9pt; margin-top: 18pt; margin-bottom: 6pt; background: #fef2f2; }
                h3    { font-size: 10pt; color: #374151; margin-top: 10pt; margin-bottom: 3pt; }
                p     { margin: 0 0 6pt 0; color: #374151; }
                ul, ol { margin: 0 0 6pt 16pt; }
                li    { color: #374151; margin-bottom: 2pt; }
                strong { color: #111827; }
                code  { font-family: "Courier New", monospace; background: #f3f4f6;
                        padding: 1pt 4pt; font-size: 8.5pt; border: 0.5pt solid #e5e7eb; }
                pre   { font-family: "Courier New", monospace; background: #f3f4f6;
                        padding: 8pt; font-size: 8pt; border: 0.5pt solid #d1d5db;
                        white-space: pre-wrap; word-wrap: break-word; }
                pre code { background: none; border: none; padding: 0; }
                table { width: 100%; border-collapse: collapse; margin-bottom: 10pt; font-size: 8.5pt; }
                th    { background: #fee2e2; color: #991b1b; padding: 5pt 7pt;
                        text-align: left; border-bottom: 1pt solid #fca5a5; font-size: 7.5pt;
                        text-transform: uppercase; letter-spacing: 0.04em; }
                td    { padding: 4pt 7pt; border-bottom: 0.5pt solid #e5e7eb; vertical-align: top; }
                tr:nth-child(even) td { background: #fafafa; }
                blockquote { border-left: 3pt solid #fca5a5; padding: 4pt 8pt;
                             margin: 6pt 0; background: #fff7f7; color: #6b7280; }
                hr    { border: none; border-top: 0.5pt solid #e5e7eb; margin: 12pt 0; }
                a     { color: #2563eb; }
              </style>
            </head>
            <body>
            """ + body + """
            </body>
            </html>
            """;
    }
}
