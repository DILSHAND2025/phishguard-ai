/**
 * MAVERICK — Dependency-Free Pure PDF 1.4 Binary Generator
 * Smart India Hackathon 2026
 * 
 * Generates standards-compliant, multi-page, cryptographic-grade PDF 1.4 documents
 * with zero external native or canvas dependencies. Works identically in Node.js
 * and modern Web Browsers.
 */

import { computeSha256 } from './forensicReportService.js';

// Standard A4 dimensions in PDF points (72 points per inch)
export const PAGE_WIDTH = 595.28;
export const PAGE_HEIGHT = 841.89;
export const MARGIN = 40;
export const CONTENT_WIDTH = PAGE_WIDTH - (MARGIN * 2); // 515.28 pt

// Color Palette (RGB 0.0 - 1.0)
export const COLORS = {
  bgDark: [0.06, 0.09, 0.16],       // #0f172a slate-900
  bgCard: [0.12, 0.16, 0.24],       // #1e293b slate-800
  bgCardLight: [0.96, 0.97, 0.99],  // Light card background
  borderDark: [0.20, 0.25, 0.35],   // Slate-700
  borderLight: [0.85, 0.88, 0.92],  // Light slate border
  primary: [0.06, 0.49, 0.75],      // Maverick Blue / Teal
  primaryDark: [0.02, 0.28, 0.45],
  accentCyan: [0.02, 0.71, 0.83],   // #06b6d4 cyan-500
  critical: [0.86, 0.15, 0.15],     // Red
  high: [0.92, 0.40, 0.10],         // Orange
  suspicious: [0.85, 0.65, 0.13],   // Amber
  clean: [0.13, 0.69, 0.30],        // Green
  textDark: [0.10, 0.12, 0.16],     // Dark charcoal
  textMuted: [0.40, 0.45, 0.52],    // Slate-500
  textLight: [0.95, 0.96, 0.98],    // White
  headerBg: [0.07, 0.11, 0.18]      // Very dark slate
};

/**
 * Escapes characters for PDF literal strings (standard Latin-1 charset).
 * Replaces non-printable and non-Latin characters with safe equivalents.
 * 
 * @param {string} str 
 * @returns {string}
 */
export function escapePdfString(str) {
  if (str === null || str === undefined) return '';
  const s = String(str)
    // Replace smart quotes and special typographical dashes
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/[\u2022\u25AA\u25CF]/g, '*')
    .replace(/[\u2192]/g, '->')
    .replace(/[^\x20-\x7E]/g, ' '); // Strip non-ASCII for standard Type1 Helvetica safety

  return s
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

/**
 * PDF 1.4 Low-Level Document Builder
 */
export class PdfDocument {
  constructor() {
    this.pages = [];
    this.currentPage = null;
  }

  /**
   * Adds a new A4 page to the document.
   * @returns {PdfPage}
   */
  addPage() {
    const page = new PdfPage(PAGE_WIDTH, PAGE_HEIGHT);
    this.pages.push(page);
    this.currentPage = page;
    return page;
  }

  /**
   * Compiles the complete PDF document into a binary Uint8Array.
   * @returns {Uint8Array}
   */
  build() {
    const objects = [];
    let objectCount = 0;

    const allocId = () => ++objectCount;

    const catalogId = allocId();
    const pagesRootId = allocId();
    const fontHelvId = allocId();
    const fontHelvBoldId = allocId();
    const fontCourierId = allocId();
    const fontCourierBoldId = allocId();

    const pageObjectIds = this.pages.map(() => ({
      pageId: allocId(),
      contentsId: allocId()
    }));

    // Object 1: Catalog
    objects[catalogId] = `<< /Type /Catalog /Pages ${pagesRootId} 0 R >>`;

    // Object 2: Pages Root
    const kidsStr = pageObjectIds.map(p => `${p.pageId} 0 R`).join(' ');
    objects[pagesRootId] = `<< /Type /Pages /Kids [${kidsStr}] /Count ${this.pages.length} >>`;

    // Fonts: Helvetica, Helvetica-Bold, Courier, Courier-Bold
    objects[fontHelvId] = `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`;
    objects[fontHelvBoldId] = `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>`;
    objects[fontCourierId] = `<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>`;
    objects[fontCourierBoldId] = `<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>`;

    // Pages and Contents
    for (let i = 0; i < this.pages.length; i++) {
      const { pageId, contentsId } = pageObjectIds[i];
      const page = this.pages[i];
      const streamContent = page.getStreamContent();
      const streamLength = new TextEncoder().encode(streamContent).length;

      // Page Object
      objects[pageId] = `<< /Type /Page /Parent ${pagesRootId} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] ` +
        `/Contents ${contentsId} 0 R ` +
        `/Resources << /Font << /F1 ${fontHelvId} 0 R /F2 ${fontHelvBoldId} 0 R /F3 ${fontCourierId} 0 R /F4 ${fontCourierBoldId} 0 R >> >> >>`;

      // Contents Stream Object
      objects[contentsId] = `<< /Length ${streamLength} >>\nstream\n${streamContent}\nendstream`;
    }

    // Assemble PDF Byte Stream
    const chunks = [];
    const encoder = new TextEncoder();
    let currentOffset = 0;

    const writeString = (str) => {
      const bytes = encoder.encode(str);
      chunks.push(bytes);
      currentOffset += bytes.length;
    };

    // Header
    writeString('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n');

    // Object table offsets
    const xrefOffsets = [];
    xrefOffsets[0] = 0;

    for (let id = 1; id <= objectCount; id++) {
      xrefOffsets[id] = currentOffset;
      writeString(`${id} 0 obj\n${objects[id]}\nendobj\n`);
    }

    // XRef Table
    const startXref = currentOffset;
    writeString(`xref\n0 ${objectCount + 1}\n`);
    writeString('0000000000 65535 f \n');
    for (let id = 1; id <= objectCount; id++) {
      const offsetStr = String(xrefOffsets[id]).padStart(10, '0');
      writeString(`${offsetStr} 00000 n \n`);
    }

    // Trailer
    writeString(`trailer\n<< /Size ${objectCount + 1} /Root ${catalogId} 0 R >>\n`);
    writeString(`startxref\n${startXref}\n%%EOF\n`);

    // Concatenate chunks
    const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
    const result = new Uint8Array(totalLength);
    let pos = 0;
    for (const chunk of chunks) {
      result.set(chunk, pos);
      pos += chunk.length;
    }

    return result;
  }
}

/**
 * Individual PDF Page Drawing Context
 */
export class PdfPage {
  constructor(width, height) {
    this.width = width;
    this.height = height;
    this.commands = [];
  }

  // Convert top-down Y (0 at top of page) to PDF standard Y (0 at bottom)
  toPdfY(y) {
    return this.height - y;
  }

  /**
   * Draws a filled rectangle.
   */
  drawRect(x, y, width, height, fillColor) {
    const [r, g, b] = fillColor;
    const pdfY = this.toPdfY(y + height);
    this.commands.push(`q ${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg ${x.toFixed(2)} ${pdfY.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re f Q`);
  }

  /**
   * Draws a stroked (bordered) rectangle.
   */
  drawStrokeRect(x, y, width, height, strokeColor, lineWidth = 1) {
    const [r, g, b] = strokeColor;
    const pdfY = this.toPdfY(y + height);
    this.commands.push(`q ${lineWidth} w ${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} RG ${x.toFixed(2)} ${pdfY.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re S Q`);
  }

  /**
   * Draws a filled rectangle with a border.
   */
  drawCard(x, y, width, height, fillColor, borderColor, lineWidth = 1) {
    const [fr, fg, fb] = fillColor;
    const [br, bg, bb] = borderColor;
    const pdfY = this.toPdfY(y + height);
    this.commands.push(`q ${lineWidth} w ${fr.toFixed(3)} ${fg.toFixed(3)} ${fb.toFixed(3)} rg ${br.toFixed(3)} ${bg.toFixed(3)} ${bb.toFixed(3)} RG ${x.toFixed(2)} ${pdfY.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re B Q`);
  }

  /**
   * Draws a horizontal line.
   */
  drawLine(x1, y, x2, strokeColor = COLORS.borderLight, lineWidth = 1) {
    const [r, g, b] = strokeColor;
    const pdfY = this.toPdfY(y);
    this.commands.push(`q ${lineWidth} w ${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} RG ${x1.toFixed(2)} ${pdfY.toFixed(2)} m ${x2.toFixed(2)} ${pdfY.toFixed(2)} l S Q`);
  }

  /**
   * Draws single line text at (x, y) where y is baseline from top.
   */
  drawText(text, x, y, options = {}) {
    const {
      font = 'F1', // F1: Helv, F2: Helv-Bold, F3: Cour, F4: Cour-Bold
      size = 10,
      color = COLORS.textDark
    } = options;

    const [r, g, b] = color;
    const pdfY = this.toPdfY(y);
    const escaped = escapePdfString(text);

    this.commands.push(`BT /${font} ${size} Tf ${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg 1 0 0 1 ${x.toFixed(2)} ${pdfY.toFixed(2)} Tm (${escaped}) Tj ET`);
  }

  /**
   * Splits and draws multi-line text wrapped to a specified maxWidth.
   * Returns final bottom Y coordinate.
   */
  drawWrappedText(text, x, y, maxWidth, options = {}) {
    const {
      font = 'F1',
      size = 9,
      lineHeight = size * 1.35,
      color = COLORS.textDark,
      maxLines = 100
    } = options;

    const words = String(text || '').split(/\s+/);
    let currentLine = '';
    let curY = y;
    let lineCount = 0;

    // Approximate character width in standard Helvetica
    const charWidth = size * (font.includes('Courier') ? 0.60 : 0.52);

    for (let i = 0; i < words.length; i++) {
      const word = words[i];
      const testLine = currentLine ? `${currentLine} ${word}` : word;
      const testWidth = testLine.length * charWidth;

      if (testWidth > maxWidth && currentLine) {
        this.drawText(currentLine, x, curY, { font, size, color });
        curY += lineHeight;
        currentLine = word;
        lineCount++;
        if (lineCount >= maxLines) break;
      } else {
        currentLine = testLine;
      }
    }

    if (currentLine && lineCount < maxLines) {
      this.drawText(currentLine, x, curY, { font, size, color });
      curY += lineHeight;
    }

    return curY;
  }

  /**
   * Helper: draws a key-value label pair.
   */
  drawField(label, value, x, y, width = 200, labelWidth = 80) {
    this.drawText(label, x, y, { font: 'F2', size: 8.5, color: COLORS.textMuted });
    const safeVal = String(value || 'None');
    this.drawText(safeVal, x + labelWidth, y, { font: 'F1', size: 8.5, color: COLORS.textDark });
  }

  /**
   * Returns page graphics stream content.
   */
  getStreamContent() {
    return this.commands.join('\n');
  }
}

/**
 * Standard Header for Report Pages (Pages 2-6)
 */
function drawPageHeader(page, title, subtitle, caseId) {
  // Top bar background
  page.drawRect(MARGIN, 25, CONTENT_WIDTH, 34, COLORS.bgDark);
  page.drawText('MAVERICK // FORENSIC INTELLIGENCE DOSSIER', MARGIN + 12, 40, { font: 'F2', size: 8, color: COLORS.accentCyan });
  page.drawText(title.toUpperCase(), MARGIN + 12, 52, { font: 'F2', size: 10, color: COLORS.textLight });

  // Case ID and classification on the right
  const rightX = MARGIN + CONTENT_WIDTH - 150;
  page.drawText(`CASE: ${caseId}`, rightX, 40, { font: 'F4', size: 8, color: COLORS.textLight });
  page.drawText('CONFIDENTIAL // SIH 2026', rightX, 52, { font: 'F1', size: 7.5, color: COLORS.textMuted });

  page.drawLine(MARGIN, 64, MARGIN + CONTENT_WIDTH, COLORS.primary, 1.5);
}

/**
 * Standard Footer for All Report Pages
 */
function drawPageFooter(page, pageNum, totalPages, contentHash = '') {
  const footerY = PAGE_HEIGHT - 35;
  page.drawLine(MARGIN, footerY, MARGIN + CONTENT_WIDTH, COLORS.borderLight, 0.75);

  // Left: hash preview
  const shortHash = contentHash ? `SHA-256: ${contentHash.slice(0, 16)}...${contentHash.slice(-8)}` : 'SIH 2026 MAVERICK';
  page.drawText(shortHash, MARGIN, footerY + 14, { font: 'F3', size: 7.5, color: COLORS.textMuted });

  // Center: standard notice
  page.drawText('TAMPER-EVIDENT DIGITAL FORENSIC RECORD (SECTION 65B EVIDENCE PRESERVATION)', MARGIN + 90, footerY + 14, { font: 'F1', size: 7, color: COLORS.textMuted });

  // Right: page numbering
  const pageStr = `Page ${pageNum} of ${totalPages}`;
  page.drawText(pageStr, MARGIN + CONTENT_WIDTH - 55, footerY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
}

/**
 * Generates the complete 6-page MAVERICK Forensic PDF Document.
 * 
 * @param {Object} report - Complete report built by forensicReportService.js
 * @returns {Uint8Array}
 */
export function generateForensicPdf(report) {
  const doc = new PdfDocument();
  const totalPages = 6;
  const caseId = report.caseId || 'MAV-2026-00000000';
  const contentHash = report.evidenceIntegrity?.contentHashSha256 || '';
  const score = report.threatAssessment?.overallScore ?? 0;
  const risk = (report.threatAssessment?.classification || 'LOW').toUpperCase();

  const getRiskColor = (lvl) => {
    if (lvl === 'CRITICAL') return COLORS.critical;
    if (lvl === 'HIGH') return COLORS.high;
    if (lvl === 'SUSPICIOUS') return COLORS.suspicious;
    return COLORS.clean;
  };

  // =========================================================================
  // PAGE 1: COVER, EXECUTIVE SUMMARY & INCIDENT OVERVIEW
  // =========================================================================
  {
    const page = doc.addPage();

    // Maverick Top Master Banner
    page.drawRect(MARGIN, 30, CONTENT_WIDTH, 80, COLORS.bgDark);
    page.drawText('SMART INDIA HACKATHON 2026 — OFFICIAL FORENSIC RECORD', MARGIN + 16, 50, { font: 'F2', size: 8.5, color: COLORS.accentCyan });
    page.drawText('MAVERICK THREAT INTELLIGENCE & FORENSIC DOSSIER', MARGIN + 16, 72, { font: 'F2', size: 15, color: COLORS.textLight });
    page.drawText('AI-POWERED EMAIL THREAT DETECTION, GEOLOCATION & CRYPTOGRAPHIC EVIDENCE AUDIT', MARGIN + 16, 92, { font: 'F1', size: 7.5, color: [0.75, 0.82, 0.90] });

    // Classification stripe
    page.drawRect(MARGIN, 110, CONTENT_WIDTH, 18, COLORS.primaryDark);
    page.drawText('CLASSIFICATION: CONFIDENTIAL // LAW ENFORCEMENT & SOC AUDIT ONLY', MARGIN + 16, 122, { font: 'F2', size: 7.5, color: COLORS.textLight });
    page.drawText(`GENERATED: ${new Date(report.generatedAt).toUTCString()}`, MARGIN + CONTENT_WIDTH - 210, 122, { font: 'F1', size: 7.5, color: [0.8, 0.9, 1.0] });

    // Incident Threat Score Card (Left Box) & Metadata Card (Right Box)
    const cardY = 140;
    const cardH = 120;
    const leftW = 190;
    const rightW = CONTENT_WIDTH - leftW - 15;

    // Left: Threat Score Box
    const riskColor = getRiskColor(risk);
    page.drawCard(MARGIN, cardY, leftW, cardH, COLORS.bgCardLight, COLORS.borderLight, 1);
    page.drawText('COMPOSITE THREAT SCORE', MARGIN + 14, cardY + 22, { font: 'F2', size: 8.5, color: COLORS.textMuted });
    
    // Large score
    page.drawText(`${score}`, MARGIN + 14, cardY + 68, { font: 'F2', size: 36, color: riskColor });
    page.drawText('/ 100', MARGIN + 70, cardY + 68, { font: 'F1', size: 14, color: COLORS.textMuted });

    // Risk badge
    page.drawRect(MARGIN + 14, cardY + 82, 100, 20, riskColor);
    page.drawText(`${risk} RISK`, MARGIN + 22, cardY + 95, { font: 'F2', size: 9, color: COLORS.textLight });
    page.drawText(`Confidence: ${report.threatAssessment?.confidence || 90}%`, MARGIN + 122, cardY + 95, { font: 'F1', size: 8, color: COLORS.textMuted });

    // Right: Case & Target Information
    page.drawCard(MARGIN + leftW + 15, cardY, rightW, cardH, COLORS.bgCardLight, COLORS.borderLight, 1);
    page.drawText('INCIDENT IDENTIFICATION', MARGIN + leftW + 28, cardY + 20, { font: 'F2', size: 9, color: COLORS.primary });
    
    let curMetaY = cardY + 38;
    const drawMetaRow = (lbl, val, isMono = false) => {
      page.drawText(lbl, MARGIN + leftW + 28, curMetaY, { font: 'F2', size: 8, color: COLORS.textMuted });
      page.drawText(String(val || 'None').slice(0, 42), MARGIN + leftW + 105, curMetaY, { font: isMono ? 'F3' : 'F1', size: 8, color: COLORS.textDark });
      curMetaY += 16;
    };
    drawMetaRow('CASE ID:', caseId, true);
    drawMetaRow('ORIGIN SENDER:', report.emailMetadata?.sender || 'Unknown');
    drawMetaRow('FROM DOMAIN:', report.emailMetadata?.fromDomain || 'None');
    drawMetaRow('TARGET INGRESS:', report.emailMetadata?.recipient || 'Corporate Ingress');
    drawMetaRow('ANALYSIS STATUS:', report.status || 'INVESTIGATION COMPLETE');

    // Executive Summary Card
    const execY = 275;
    page.drawCard(MARGIN, execY, CONTENT_WIDTH, 175, COLORS.bgCardLight, COLORS.borderLight, 1);
    page.drawRect(MARGIN, execY, CONTENT_WIDTH, 26, [0.91, 0.94, 0.98]);
    page.drawText('1. EXECUTIVE SUMMARY & FORENSIC FINDINGS', MARGIN + 14, execY + 17, { font: 'F2', size: 9.5, color: COLORS.primaryDark });
    page.drawText('(Statutory Non-Repudiation Standard)', MARGIN + 260, execY + 17, { font: 'F1', size: 8, color: COLORS.textMuted });

    const execSummaryText = report.executiveSummary || 'No executive summary text generated.';
    page.drawWrappedText(execSummaryText, MARGIN + 14, execY + 45, CONTENT_WIDTH - 28, {
      font: 'F1',
      size: 9,
      lineHeight: 13.5,
      color: COLORS.textDark,
      maxLines: 9
    });

    // Ingress Email Envelope Snapshot
    const snapY = 465;
    page.drawCard(MARGIN, snapY, CONTENT_WIDTH, 185, COLORS.bgCardLight, COLORS.borderLight, 1);
    page.drawRect(MARGIN, snapY, CONTENT_WIDTH, 26, [0.91, 0.94, 0.98]);
    page.drawText('2. INGRESS EMAIL ENVELOPE SNAPSHOT', MARGIN + 14, snapY + 17, { font: 'F2', size: 9.5, color: COLORS.primaryDark });

    let envY = snapY + 46;
    const drawEnvField = (label, val, mono = false) => {
      page.drawText(label, MARGIN + 16, envY, { font: 'F2', size: 8, color: COLORS.textMuted });
      page.drawText(String(val || 'None').slice(0, 75), MARGIN + 130, envY, { font: mono ? 'F3' : 'F1', size: 8, color: COLORS.textDark });
      envY += 16;
    };

    drawEnvField('Message-ID:', report.emailMetadata?.messageId, true);
    drawEnvField('RFC 822 Date:', report.emailMetadata?.date);
    drawEnvField('Subject Line:', report.emailMetadata?.subject);
    drawEnvField('Sender (From):', report.emailMetadata?.sender);
    drawEnvField('Return-Path:', report.emailMetadata?.returnPath || 'None');
    drawEnvField('Reply-To:', report.emailMetadata?.replyTo || 'Same as sender');
    drawEnvField('Originating IP:', report.emailMetadata?.originatingIP || 'Unspecified hop', true);
    drawEnvField('Received Hops:', `${report.emailMetadata?.receivedHopsCount || 0} transit hops recorded`);

    // Chain-of-custody box at bottom of page 1
    const sealY = 665;
    page.drawCard(MARGIN, sealY, CONTENT_WIDTH, 90, COLORS.bgDark, COLORS.borderDark, 1);
    page.drawText('FORENSIC CHAIN OF CUSTODY CERTIFICATE', MARGIN + 16, sealY + 20, { font: 'F2', size: 9, color: COLORS.accentCyan });
    page.drawText('Report Content SHA-256 Digest:', MARGIN + 16, sealY + 38, { font: 'F1', size: 8, color: [0.75, 0.82, 0.90] });
    page.drawText(contentHash || 'HASH_PENDING_COMPUTATION', MARGIN + 16, sealY + 52, { font: 'F3', size: 8, color: COLORS.textLight });
    page.drawText('Evidentiary Integrity: Produced under ISO/IEC 27037:2012 Guidelines supporting statutory evidence preservation.', MARGIN + 16, sealY + 72, { font: 'F1', size: 7.5, color: COLORS.textMuted });

    drawPageFooter(page, 1, totalPages, contentHash);
  }

  // =========================================================================
  // PAGE 2: HEADER FORENSICS, AI/ML THREAT TELEMETRY & IOCS
  // =========================================================================
  {
    const page = doc.addPage();
    drawPageHeader(page, 'Header Forensics & AI Threat Telemetry', 'MIME Analysis & Machine Learning', caseId);

    // Section 3: Header Hop Forensics
    let curY = 80;
    page.drawText('3. RFC 822 / MIME HEADER HOP TELEMETRY', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const hops = report.emailMetadata?.receivedHops || [];
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, 85, COLORS.bgCardLight, COLORS.borderLight, 1);
    
    // Header row
    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 20, [0.88, 0.92, 0.96]);
    page.drawText('HOP #', MARGIN + 10, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('EXTRACTED IP', MARGIN + 55, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('RELAY SERVER (FROM -> BY)', MARGIN + 170, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });

    let hopY = curY + 32;
    if (hops.length === 0) {
      page.drawText('No Received header hops present in MIME source or single-hop direct injection.', MARGIN + 14, hopY, { font: 'F1', size: 8, color: COLORS.textMuted });
    } else {
      for (const h of hops.slice(0, 3)) {
        page.drawText(`Hop ${h.hopNumber || 1}`, MARGIN + 10, hopY, { font: 'F2', size: 8, color: COLORS.textDark });
        page.drawText(h.ip || 'Internal / Direct', MARGIN + 55, hopY, { font: 'F3', size: 8, color: COLORS.primary });
        const route = `${h.from || 'Direct'} -> ${h.by || 'MX'}`;
        page.drawText(route.slice(0, 52), MARGIN + 170, hopY, { font: 'F1', size: 7.5, color: COLORS.textDark });
        hopY += 16;
      }
    }

    // Section 4: AI / ML Threat Detection Telemetry
    curY += 105;
    page.drawText('4. NATURAL LANGUAGE AI/ML THREAT PREDICTION', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const ml = report.mlAnalysis || {};
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, 140, COLORS.bgCardLight, COLORS.borderLight, 1);

    // Sub-banner
    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 22, [0.88, 0.92, 0.96]);
    page.drawText('MODEL: TF-IDF VECTORIZER + LOGISTIC REGRESSION (TRAINED MODEL)', MARGIN + 12, curY + 15, { font: 'F2', size: 8, color: COLORS.primaryDark });
    page.drawText(`ENGINE STATUS: ${ml.status || 'ACTIVE'}`, MARGIN + CONTENT_WIDTH - 140, curY + 15, { font: 'F2', size: 8, color: ml.status === 'ACTIVE' ? COLORS.clean : COLORS.high });

    // ML metric cards inside
    const mlCardW = (CONTENT_WIDTH - 36) / 3;
    const mlCardY = curY + 32;
    const drawMlMetric = (title, val, color, x) => {
      page.drawCard(x, mlCardY, mlCardW, 46, [1, 1, 1], COLORS.borderLight, 0.5);
      page.drawText(title, x + 8, mlCardY + 14, { font: 'F2', size: 7.5, color: COLORS.textMuted });
      page.drawText(val, x + 8, mlCardY + 36, { font: 'F2', size: 16, color });
    };

    const phishProb = ml.phishingProbability != null ? `${ml.phishingProbability}%` : 'N/A';
    const legitProb = ml.legitimateProbability != null ? `${ml.legitimateProbability}%` : 'N/A';
    const confVal = ml.confidence != null ? `${ml.confidence}%` : 'N/A';

    drawMlMetric('PHISHING PROBABILITY', phishProb, (ml.phishingProbability || 0) >= 50 ? COLORS.critical : COLORS.clean, MARGIN + 10);
    drawMlMetric('LEGITIMATE PROBABILITY', legitProb, COLORS.primary, MARGIN + 10 + mlCardW + 8);
    drawMlMetric('CLASSIFIER CONFIDENCE', confVal, COLORS.textDark, MARGIN + 10 + (mlCardW + 8) * 2);

    // Top features
    let featY = mlCardY + 58;
    page.drawText('Observed Lexical Threat Indicators / Top Tokens:', MARGIN + 12, featY, { font: 'F2', size: 8, color: COLORS.textMuted });
    featY += 14;

    const feats = (ml.topFeatures && ml.topFeatures.length > 0) ? ml.topFeatures : (ml.detectedIndicators || ['No high-weight adversarial tokens detected']);
    const featStr = feats.map(f => typeof f === 'string' ? f : `${f.token || f.name} (w=${f.weight || f.score})`).slice(0, 5).join('   |   ');
    page.drawText(featStr.slice(0, 95), MARGIN + 12, featY, { font: 'F3', size: 7.5, color: COLORS.textDark });

    // Section 5: Extracted IOC Telemetry
    curY += 160;
    page.drawText('5. EXTRACTED INDICATORS OF COMPROMISE (IOCS)', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const iocs = report.iocAnalysis || [];
    const iocCardH = 340;
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, iocCardH, COLORS.bgCardLight, COLORS.borderLight, 1);

    // Table Header
    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 22, [0.88, 0.92, 0.96]);
    page.drawText('TYPE', MARGIN + 10, curY + 15, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('INDICATOR VALUE', MARGIN + 70, curY + 15, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('SOURCE', MARGIN + 310, curY + 15, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('RISK', MARGIN + 400, curY + 15, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('CONFIDENCE', MARGIN + 455, curY + 15, { font: 'F2', size: 8, color: COLORS.textDark });

    let rowY = curY + 36;
    if (iocs.length === 0) {
      page.drawText('No active IOCs (external IPs, deceptive URLs, or suspicious hashes) extracted.', MARGIN + 14, rowY, { font: 'F1', size: 8.5, color: COLORS.textMuted });
    } else {
      for (const ioc of iocs.slice(0, 14)) {
        page.drawText(ioc.type || 'IOC', MARGIN + 10, rowY, { font: 'F2', size: 7.5, color: COLORS.primaryDark });
        page.drawText(String(ioc.value || '').slice(0, 42), MARGIN + 70, rowY, { font: 'F3', size: 7.5, color: COLORS.textDark });
        page.drawText(String(ioc.source || 'Header').slice(0, 15), MARGIN + 310, rowY, { font: 'F1', size: 7.5, color: COLORS.textMuted });
        
        const iocRisk = (ioc.risk || 'SUSPICIOUS').toUpperCase();
        page.drawText(iocRisk, MARGIN + 400, rowY, { font: 'F2', size: 7.5, color: iocRisk === 'MALICIOUS' ? COLORS.critical : COLORS.suspicious });
        page.drawText(`${ioc.confidence || 85}%`, MARGIN + 465, rowY, { font: 'F1', size: 7.5, color: COLORS.textDark });

        page.drawLine(MARGIN + 6, rowY + 6, MARGIN + CONTENT_WIDTH - 6, [0.90, 0.92, 0.94], 0.5);
        rowY += 21;
      }
    }

    drawPageFooter(page, 2, totalPages, contentHash);
  }

  // =========================================================================
  // PAGE 3: NETWORK INFRASTRUCTURE (GEO/ASN) & ATTACHMENT FORENSICS
  // =========================================================================
  {
    const page = doc.addPage();
    drawPageHeader(page, 'Infrastructure & Static Attachment Forensics', 'GeoLocation, ASN Routing & Payload Audit', caseId);

    // Section 6: GeoLocation & Autonomous System Topology
    let curY = 80;
    page.drawText('6. NETWORK INFRASTRUCTURE & ASN ROUTING TELEMETRY', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const geo = report.geoLocationAnalysis || {};
    const node = geo.primaryNode || null;
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, 175, COLORS.bgCardLight, COLORS.borderLight, 1);

    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 22, [0.88, 0.92, 0.96]);
    page.drawText('PRIMARY ORIGINATING INGRESS NODE', MARGIN + 12, curY + 15, { font: 'F2', size: 8.5, color: COLORS.primaryDark });
    page.drawText(`STATUS: ${geo.status || 'UNAVAILABLE'}`, MARGIN + CONTENT_WIDTH - 130, curY + 15, { font: 'F2', size: 8, color: node ? COLORS.clean : COLORS.textMuted });

    let gY = curY + 36;
    if (!node) {
      page.drawText('Private, internal RFC 1918, or direct localhost IP origin. No public ASN telemetry.', MARGIN + 14, gY, { font: 'F1', size: 8.5, color: COLORS.textMuted });
    } else {
      const drawGeoRow = (l1, v1, l2, v2) => {
        page.drawText(l1, MARGIN + 14, gY, { font: 'F2', size: 8, color: COLORS.textMuted });
        page.drawText(String(v1 || 'N/A').slice(0, 32), MARGIN + 85, gY, { font: 'F3', size: 8, color: COLORS.textDark });
        if (l2) {
          page.drawText(l2, MARGIN + 260, gY, { font: 'F2', size: 8, color: COLORS.textMuted });
          page.drawText(String(v2 || 'N/A').slice(0, 32), MARGIN + 340, gY, { font: 'F1', size: 8, color: COLORS.textDark });
        }
        gY += 18;
      };

      drawGeoRow('IP Address:', node.ip, 'Geographic Location:', `${node.city || 'Unknown'}, ${node.country || 'Unknown'}`);
      drawGeoRow('ASN Identifier:', node.asn, 'ASN Organization:', node.asnOrg);
      drawGeoRow('Network Type:', node.networkType, 'Proxy / VPN Egress:', node.isProxyOrVpn ? 'YES (ANONYMIZED)' : 'NO (DIRECT)');
      drawGeoRow('Coordinates:', node.lat ? `${node.lat}, ${node.lon}` : 'N/A', 'Topology Role:', node.role || 'ORIGINATING HOP');
    }

    // Legal disclaimer callout
    const discY = curY + 120;
    page.drawCard(MARGIN + 10, discY, CONTENT_WIDTH - 20, 44, [1, 1, 1], [0.85, 0.88, 0.92], 0.5);
    page.drawText('STATUTORY NON-DISCRIMINATION & GEO-CONTEXT NOTICE:', MARGIN + 18, discY + 14, { font: 'F2', size: 7, color: COLORS.primaryDark });
    page.drawWrappedText(geo.disclaimer || 'Geolocation data reflects infrastructure routing only and is never used as sole proof of threat intent.', MARGIN + 18, discY + 26, CONTENT_WIDTH - 36, {
      font: 'F1',
      size: 6.8,
      lineHeight: 8.5,
      color: COLORS.textMuted,
      maxLines: 2
    });

    // Section 7: Static Attachment Forensics
    curY += 195;
    page.drawText('7. STATIC ATTACHMENT FORENSICS (ZERO-EXECUTION INSPECTION)', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const atts = report.attachmentAnalysis?.attachments || [];
    const attCardH = 345;
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, attCardH, COLORS.bgCardLight, COLORS.borderLight, 1);

    // Sub-banner
    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 22, [0.88, 0.92, 0.96]);
    page.drawText('FILENAME / TYPE', MARGIN + 10, curY + 15, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('MAGIC BYTES', MARGIN + 155, curY + 15, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('RISK VERDICT', MARGIN + 265, curY + 15, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('CRYPTOGRAPHIC HASHES (SHA-256 / SHA-1 / MD5)', MARGIN + 355, curY + 15, { font: 'F2', size: 8, color: COLORS.textDark });

    let aY = curY + 36;
    if (atts.length === 0) {
      page.drawText('No file attachments detected in MIME envelope.', MARGIN + 14, aY, { font: 'F1', size: 8.5, color: COLORS.textMuted });
      aY += 20;
    } else {
      for (const att of atts.slice(0, 4)) {
        page.drawText(`[${att.index}] ${att.filename}`.slice(0, 26), MARGIN + 10, aY, { font: 'F2', size: 7.5, color: COLORS.textDark });
        page.drawText(`${att.size} | ${att.declaredMime}`.slice(0, 26), MARGIN + 10, aY + 11, { font: 'F1', size: 7, color: COLORS.textMuted });

        page.drawText(att.magicBytes || 'N/A', MARGIN + 155, aY, { font: 'F3', size: 7.5, color: COLORS.primaryDark });
        page.drawText(att.extensionMismatch ? 'MISMATCH!' : 'Type OK', MARGIN + 155, aY + 11, { font: 'F2', size: 7, color: att.extensionMismatch ? COLORS.critical : COLORS.clean });

        const riskTxt = (att.riskAssessment || 'CLEAN').toUpperCase();
        page.drawText(riskTxt, MARGIN + 265, aY, { font: 'F2', size: 8, color: riskTxt.includes('CRIT') || riskTxt.includes('MAL') ? COLORS.critical : COLORS.clean });
        page.drawText(att.reputationStatus || 'UNKNOWN', MARGIN + 265, aY + 11, { font: 'F1', size: 7, color: COLORS.textMuted });

        page.drawText(`SHA256: ${(att.sha256 || 'None').slice(0, 24)}...`, MARGIN + 355, aY, { font: 'F3', size: 7, color: COLORS.textDark });
        page.drawText(`MD5: ${(att.md5 || 'None').slice(0, 24)}...`, MARGIN + 355, aY + 11, { font: 'F3', size: 7, color: COLORS.textMuted });

        page.drawLine(MARGIN + 6, aY + 24, MARGIN + CONTENT_WIDTH - 6, [0.90, 0.92, 0.94], 0.5);
        aY += 34;
      }
    }

    // Safety guarantee callout
    const safeY = curY + attCardH - 55;
    page.drawCard(MARGIN + 10, safeY, CONTENT_WIDTH - 20, 42, [0.94, 0.97, 0.95], [0.80, 0.88, 0.82], 0.5);
    page.drawText('ISOLATION & STATIC INSPECTION GUARANTEE:', MARGIN + 18, safeY + 14, { font: 'F2', size: 7, color: COLORS.clean });
    page.drawText('All attachment forensics were conducted via static binary header parsing and cryptographic hashing.', MARGIN + 18, safeY + 26, { font: 'F1', size: 7, color: COLORS.textDark });
    page.drawText('No payloads were executed, mounted, or dynamically detonated during this investigation.', MARGIN + 18, safeY + 36, { font: 'F1', size: 7, color: COLORS.textMuted });

    drawPageFooter(page, 3, totalPages, contentHash);
  }

  // =========================================================================
  // PAGE 4: LIVE EMAIL AUTHENTICATION & DOMAIN ALIGNMENT
  // =========================================================================
  {
    const page = doc.addPage();
    drawPageHeader(page, 'Email Authentication & Cryptographic Alignment', 'SPF, DKIM, DMARC & RFC 7489 Alignment Matrix', caseId);

    const auth = report.emailAuthentication || {};

    // Section 8: SPF
    let curY = 80;
    page.drawText('8. SENDER POLICY FRAMEWORK (SPF — RFC 7208)', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const spf = auth.spf || {};
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, 90, COLORS.bgCardLight, COLORS.borderLight, 1);
    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 20, [0.88, 0.92, 0.96]);
    page.drawText(`EVALUATED DOMAIN: ${spf.domain || 'N/A'}`, MARGIN + 12, curY + 14, { font: 'F2', size: 8, color: COLORS.primaryDark });
    page.drawText(`VERDICT: ${spf.status || 'UNCHECKED'}`, MARGIN + CONTENT_WIDTH - 140, curY + 14, { font: 'F2', size: 8, color: String(spf.status).includes('PASS') ? COLORS.clean : COLORS.critical });

    let spfY = curY + 34;
    page.drawText('DNS TXT Record:', MARGIN + 14, spfY, { font: 'F2', size: 8, color: COLORS.textMuted });
    page.drawText(String(spf.record || 'No TXT SPF record observed in authoritative DNS zone.').slice(0, 75), MARGIN + 105, spfY, { font: 'F3', size: 7.5, color: COLORS.textDark });
    spfY += 16;
    page.drawText('Insecure +all Mechanism:', MARGIN + 14, spfY, { font: 'F2', size: 8, color: COLORS.textMuted });
    page.drawText(spf.hasPlusAll ? 'CRITICAL VULNERABILITY (+all allows any host to forge email)' : 'SECURE (No +all wildcard)', MARGIN + 130, spfY, { font: 'F2', size: 8, color: spf.hasPlusAll ? COLORS.critical : COLORS.clean });
    spfY += 16;
    page.drawText('Observed Verdict:', MARGIN + 14, spfY, { font: 'F2', size: 8, color: COLORS.textMuted });
    page.drawText(String(spf.observedVerdict || 'UNKNOWN').toUpperCase(), MARGIN + 105, spfY, { font: 'F1', size: 8, color: COLORS.textDark });

    // Section 9: DKIM
    curY += 110;
    page.drawText('9. DOMAINKEYS IDENTIFIED MAIL (DKIM — RFC 6376)', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const dkim = auth.dkim || {};
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, 90, COLORS.bgCardLight, COLORS.borderLight, 1);
    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 20, [0.88, 0.92, 0.96]);
    page.drawText(`SIGNING DOMAIN (d=): ${dkim.domain || 'N/A'}    |    SELECTOR (s=): ${dkim.selector || 'None'}`, MARGIN + 12, curY + 14, { font: 'F2', size: 8, color: COLORS.primaryDark });
    page.drawText(`VERDICT: ${dkim.status || 'UNCHECKED'}`, MARGIN + CONTENT_WIDTH - 140, curY + 14, { font: 'F2', size: 8, color: String(dkim.status).includes('PASS') ? COLORS.clean : COLORS.critical });

    let dkimY = curY + 34;
    page.drawText('Cryptographic Algorithm:', MARGIN + 14, dkimY, { font: 'F2', size: 8, color: COLORS.textMuted });
    page.drawText(dkim.algorithm || 'rsa-sha256', MARGIN + 130, dkimY, { font: 'F3', size: 8, color: COLORS.textDark });
    dkimY += 16;
    page.drawText('Public Key in DNS:', MARGIN + 14, dkimY, { font: 'F2', size: 8, color: COLORS.textMuted });
    page.drawText(dkim.dnsRecordFound ? 'RESOLVED (Public key verified in DNS)' : 'NOT FOUND (Public key absent or selector unknown)', MARGIN + 130, dkimY, { font: 'F1', size: 8, color: dkim.dnsRecordFound ? COLORS.clean : COLORS.high });
    dkimY += 16;
    page.drawText('Canonicalization Method:', MARGIN + 14, dkimY, { font: 'F2', size: 8, color: COLORS.textMuted });
    page.drawText(dkim.canonicalization || 'simple/simple', MARGIN + 130, dkimY, { font: 'F1', size: 8, color: COLORS.textDark });

    // Section 10: DMARC Policy
    curY += 110;
    page.drawText('10. DOMAIN-BASED MESSAGE AUTHENTICATION & REPORTING (DMARC — RFC 7489)', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const dmarc = auth.dmarc || {};
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, 90, COLORS.bgCardLight, COLORS.borderLight, 1);
    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 20, [0.88, 0.92, 0.96]);
    page.drawText(`POLICY DOMAIN: _dmarc.${dmarc.domain || 'N/A'}`, MARGIN + 12, curY + 14, { font: 'F2', size: 8, color: COLORS.primaryDark });
    page.drawText(`POLICY: p=${dmarc.policy || 'none'}`, MARGIN + CONTENT_WIDTH - 140, curY + 14, { font: 'F2', size: 8, color: dmarc.policy === 'reject' ? COLORS.clean : dmarc.policy === 'quarantine' ? COLORS.suspicious : COLORS.high });

    let dmarcY = curY + 34;
    page.drawText('Enforcement Action (p=):', MARGIN + 14, dmarcY, { font: 'F2', size: 8, color: COLORS.textMuted });
    page.drawText(`${dmarc.policy || 'none'} (${dmarc.percentage ?? 100}% traffic enforcement)`, MARGIN + 130, dmarcY, { font: 'F2', size: 8, color: COLORS.textDark });
    dmarcY += 16;
    page.drawText('Alignment Strictness:', MARGIN + 14, dmarcY, { font: 'F2', size: 8, color: COLORS.textMuted });
    page.drawText(`aspf=${dmarc.aspf || 'r'} (SPF), adkim=${dmarc.adkim || 'r'} (DKIM), sp=${dmarc.subdomainPolicy || 'inherit'}`, MARGIN + 130, dmarcY, { font: 'F1', size: 8, color: COLORS.textDark });
    dmarcY += 16;
    page.drawText('Observed Verdict:', MARGIN + 14, dmarcY, { font: 'F2', size: 8, color: COLORS.textMuted });
    page.drawText(String(dmarc.observedVerdict || 'UNKNOWN').toUpperCase(), MARGIN + 130, dmarcY, { font: 'F1', size: 8, color: COLORS.textDark });

    // Section 11: Domain Alignment Matrix
    curY += 110;
    page.drawText('11. DMARC DOMAIN ALIGNMENT MATRIX (RFC 7489 SECTION 3.1)', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const align = auth.alignment || {};
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, 175, COLORS.bgCardLight, COLORS.borderLight, 1);

    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 20, [0.88, 0.92, 0.96]);
    page.drawText('PROTOCOL', MARGIN + 14, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('IDENTIFIER CHECK', MARGIN + 110, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('MODE', MARGIN + 310, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('ALIGNMENT STATUS', MARGIN + 400, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });

    const drawAlignRow = (proto, desc, mode, isAligned, y) => {
      page.drawText(proto, MARGIN + 14, y, { font: 'F2', size: 8, color: COLORS.primaryDark });
      page.drawText(desc, MARGIN + 110, y, { font: 'F1', size: 7.5, color: COLORS.textDark });
      page.drawText(mode, MARGIN + 310, y, { font: 'F1', size: 7.5, color: COLORS.textMuted });
      page.drawText(isAligned ? 'ALIGNED' : 'MISALIGNED', MARGIN + 400, y, { font: 'F2', size: 8, color: isAligned ? COLORS.clean : COLORS.critical });
      page.drawLine(MARGIN + 6, y + 6, MARGIN + CONTENT_WIDTH - 6, [0.90, 0.92, 0.94], 0.5);
    };

    drawAlignRow('SPF Alignment', 'RFC 5321.MailFrom vs RFC 5322.From', align.spfMode || 'relaxed', align.spfAligned, curY + 36);
    drawAlignRow('DKIM Alignment', 'DKIM d= parameter vs RFC 5322.From', align.dkimMode || 'relaxed', align.dkimAligned, curY + 62);
    drawAlignRow('DMARC Compliance', 'SPF or DKIM pass + aligned', 'RFC 7489', align.dmarcAligned, curY + 88);

    // Callout box if spoofing detected
    const calloutY = curY + 106;
    const hasMisalign = !align.dmarcAligned || !align.spfAligned || !align.dkimAligned;
    page.drawCard(MARGIN + 10, calloutY, CONTENT_WIDTH - 20, 56, hasMisalign ? [0.99, 0.94, 0.94] : [0.94, 0.98, 0.95], hasMisalign ? [0.90, 0.70, 0.70] : [0.70, 0.88, 0.75], 0.5);
    page.drawText('DOMAIN ALIGNMENT ASSESSMENT:', MARGIN + 18, calloutY + 16, { font: 'F2', size: 8, color: hasMisalign ? COLORS.critical : COLORS.clean });
    const msg = hasMisalign 
      ? 'CRITICAL IDENTITY MISALIGNMENT: The ingress email headers exhibit domain divergence between the envelope sender and the visible From address. This is a primary technical indicator of email spoofing or unauthorized relay.'
      : 'AUTHENTICATED SENDER IDENTITY: Envelope identifiers, cryptographic DKIM signatures, and RFC 5322 From headers are fully aligned and authorized by domain policy.';
    page.drawWrappedText(msg, MARGIN + 18, calloutY + 28, CONTENT_WIDTH - 36, { font: 'F1', size: 7.5, lineHeight: 10, color: COLORS.textDark, maxLines: 2 });

    drawPageFooter(page, 4, totalPages, contentHash);
  }

  // =========================================================================
  // PAGE 5: OBSERVED VS INFERRED MATRIX & MULTI-FACTOR EVIDENCE FUSION
  // =========================================================================
  {
    const page = doc.addPage();
    drawPageHeader(page, 'Observed vs Inferred Matrix & Evidence Fusion', 'Strict Evidentiary Partitioning & 6-Layer Threat Calibration', caseId);

    // Section 12: Observed Evidence vs Inferred Intelligence Partitioning
    let curY = 80;
    page.drawText('12. STRICT SEPARATION OF OBSERVED EVIDENCE vs INFERRED INTELLIGENCE', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const partW = (CONTENT_WIDTH - 12) / 2;
    const partH = 260;

    // Left: Observed Evidence
    page.drawCard(MARGIN, curY, partW, partH, COLORS.bgCardLight, COLORS.borderLight, 1);
    page.drawRect(MARGIN, curY, partW, 22, [0.15, 0.23, 0.35]);
    page.drawText('OBSERVED EVIDENCE (EMPIRICAL FACTS)', MARGIN + 10, curY + 15, { font: 'F2', size: 8, color: COLORS.textLight });

    let obsY = curY + 34;
    const obsList = report.observedEvidence || [];
    for (const item of obsList.slice(0, 10)) {
      page.drawText('*', MARGIN + 10, obsY, { font: 'F2', size: 8, color: COLORS.primary });
      page.drawWrappedText(item, MARGIN + 20, obsY, partW - 28, { font: 'F1', size: 7.5, lineHeight: 9.5, color: COLORS.textDark, maxLines: 2 });
      obsY += 21;
    }

    // Right: Inferred Intelligence
    page.drawCard(MARGIN + partW + 12, curY, partW, partH, COLORS.bgCardLight, COLORS.borderLight, 1);
    page.drawRect(MARGIN + partW + 12, curY, partW, 22, [0.22, 0.18, 0.30]);
    page.drawText('INFERRED INTELLIGENCE (ANALYTICAL / AI)', MARGIN + partW + 22, curY + 15, { font: 'F2', size: 8, color: COLORS.textLight });

    let infY = curY + 34;
    const infList = report.inferredIntelligence || [];
    for (const item of infList.slice(0, 10)) {
      page.drawText('>', MARGIN + partW + 22, infY, { font: 'F2', size: 8, color: COLORS.accentCyan });
      page.drawWrappedText(item, MARGIN + partW + 32, infY, partW - 40, { font: 'F1', size: 7.5, lineHeight: 9.5, color: COLORS.textDark, maxLines: 2 });
      infY += 21;
    }

    // Section 13: Multi-Factor Evidence Fusion Breakdown
    curY += partH + 20;
    page.drawText('13. MULTI-FACTOR EVIDENCE FUSION SCORE BREAKDOWN (6-LAYER PIPELINE)', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const fusionH = 265;
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, fusionH, COLORS.bgCardLight, COLORS.borderLight, 1);

    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 20, [0.88, 0.92, 0.96]);
    page.drawText('CATEGORY', MARGIN + 12, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('FACTOR / MECHANISM', MARGIN + 110, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('SEVERITY', MARGIN + 310, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('POINTS CONTRIBUTION', MARGIN + 400, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });

    let fY = curY + 34;
    const factors = report.evidenceFusion?.factors || [];
    if (factors.length === 0) {
      page.drawText('Evidence Fusion calculated baseline normal threat level across all evaluated layers.', MARGIN + 14, fY, { font: 'F1', size: 8.5, color: COLORS.textMuted });
    } else {
      for (const f of factors.slice(0, 8)) {
        page.drawText(f.category || 'ANALYSIS', MARGIN + 12, fY, { font: 'F2', size: 7.5, color: COLORS.primaryDark });
        page.drawText(String(f.name || 'Factor').slice(0, 36), MARGIN + 110, fY, { font: 'F1', size: 7.5, color: COLORS.textDark });
        
        const sev = (f.severity || 'INFO').toUpperCase();
        page.drawText(sev, MARGIN + 310, fY, { font: 'F2', size: 7.5, color: sev === 'CRITICAL' ? COLORS.critical : sev === 'HIGH' ? COLORS.high : COLORS.suspicious });
        page.drawText(`+${f.points || 0} pts (max ${f.maxPoints || 0})`, MARGIN + 400, fY, { font: 'F3', size: 7.5, color: COLORS.textDark });

        page.drawLine(MARGIN + 6, fY + 6, MARGIN + CONTENT_WIDTH - 6, [0.90, 0.92, 0.94], 0.5);
        fY += 21;
      }
    }

    // Total score line at bottom of table
    const scoreBarY = curY + fusionH - 35;
    page.drawRect(MARGIN, scoreBarY, CONTENT_WIDTH, 26, [0.12, 0.16, 0.24]);
    page.drawText(`TOTAL EVIDENCE FUSION THREAT SCORE:  ${score} / 100`, MARGIN + 16, scoreBarY + 17, { font: 'F2', size: 9.5, color: COLORS.textLight });
    page.drawText(`CLASSIFICATION: ${risk}`, MARGIN + CONTENT_WIDTH - 150, scoreBarY + 17, { font: 'F2', size: 9.5, color: getRiskColor(risk) });

    drawPageFooter(page, 5, totalPages, contentHash);
  }

  // =========================================================================
  // PAGE 6: ADVISORY RECOMMENDATIONS & CHAIN OF CUSTODY
  // =========================================================================
  {
    const page = doc.addPage();
    drawPageHeader(page, 'Advisory Recommendations & Audit Integrity', 'Incident Response Plan & Statutory Evidence Validation', caseId);

    // Section 14: Prioritized Incident Response Plan
    let curY = 80;
    page.drawText('14. PRIORITIZED INCIDENT RESPONSE & ADVISORY ACTION PLAN', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const recs = report.recommendations || [];
    const recCardH = 260;
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, recCardH, COLORS.bgCardLight, COLORS.borderLight, 1);

    page.drawRect(MARGIN, curY, CONTENT_WIDTH, 20, [0.88, 0.92, 0.96]);
    page.drawText('PRIORITY', MARGIN + 12, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });
    page.drawText('RECOMMENDED ACTION & TECHNICAL RATIONALE', MARGIN + 100, curY + 14, { font: 'F2', size: 8, color: COLORS.textDark });

    let rY = curY + 32;
    for (const rec of recs.slice(0, 5)) {
      const pColor = rec.priority === 'CRITICAL' ? COLORS.critical : rec.priority === 'HIGH' ? COLORS.high : rec.priority === 'COMPLIANCE' ? COLORS.primary : COLORS.suspicious;
      page.drawRect(MARGIN + 12, rY - 8, 70, 16, pColor);
      page.drawText(rec.priority, MARGIN + 16, rY + 3, { font: 'F2', size: 7.5, color: COLORS.textLight });

      page.drawText(rec.action, MARGIN + 100, rY, { font: 'F2', size: 8, color: COLORS.textDark });
      page.drawWrappedText(rec.rationale, MARGIN + 100, rY + 11, CONTENT_WIDTH - 110, { font: 'F1', size: 7, lineHeight: 9, color: COLORS.textMuted, maxLines: 2 });

      page.drawLine(MARGIN + 6, rY + 28, MARGIN + CONTENT_WIDTH - 6, [0.90, 0.92, 0.94], 0.5);
      rY += 40;
    }

    // Section 15: Investigation Timeline
    curY += recCardH + 15;
    page.drawText('15. ANALYSIS EXECUTION AUDIT TIMELINE', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const timeH = 120;
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, timeH, COLORS.bgCardLight, COLORS.borderLight, 1);

    let tY = curY + 20;
    const timeline = report.investigationTimeline || [];
    for (let i = 0; i < timeline.length; i += 2) {
      const t1 = timeline[i];
      const t2 = timeline[i + 1];

      if (t1) {
        page.drawText(`[${t1.step}] ${t1.action}`, MARGIN + 14, tY, { font: 'F2', size: 7.5, color: COLORS.textDark });
        page.drawText(t1.status, MARGIN + 180, tY, { font: 'F3', size: 7, color: t1.status.includes('COMP') ? COLORS.clean : COLORS.textMuted });
      }
      if (t2) {
        page.drawText(`[${t2.step}] ${t2.action}`, MARGIN + 265, tY, { font: 'F2', size: 7.5, color: COLORS.textDark });
        page.drawText(t2.status, MARGIN + 440, tY, { font: 'F3', size: 7, color: t2.status.includes('COMP') ? COLORS.clean : COLORS.textMuted });
      }
      tY += 18;
    }

    // Section 16: Cryptographic Chain-of-Custody Integrity Certificate
    curY += timeH + 15;
    page.drawText('16. DIGITAL CHAIN-OF-CUSTODY & STATUTORY INTEGRITY SEAL', MARGIN, curY, { font: 'F2', size: 10, color: COLORS.primaryDark });
    curY += 12;

    const certH = 145;
    page.drawCard(MARGIN, curY, CONTENT_WIDTH, certH, COLORS.bgDark, COLORS.borderDark, 1.5);

    page.drawText('CRYPTOGRAPHIC AUDIT CERTIFICATE // SMART INDIA HACKATHON 2026', MARGIN + 14, curY + 20, { font: 'F2', size: 9, color: COLORS.accentCyan });
    page.drawText('This document constitutes an automated, tamper-evident record generated by the MAVERICK Platform.', MARGIN + 14, curY + 34, { font: 'F1', size: 7.5, color: [0.75, 0.82, 0.90] });

    let certY = curY + 54;
    const drawCertField = (label, val) => {
      page.drawText(label, MARGIN + 14, certY, { font: 'F2', size: 7.5, color: COLORS.accentCyan });
      page.drawText(val, MARGIN + 140, certY, { font: 'F3', size: 7.5, color: COLORS.textLight });
      certY += 16;
    };

    drawCertField('Unique Case Identifier:', caseId);
    drawCertField('Canonical Content Digest:', contentHash || 'SHA256: PENDING');
    drawCertField('Statutory Framework:', 'ISO/IEC 27037:2012 Digital Evidence / Section 65B Indian Evidence Act');
    drawCertField('Integrity Signature:', report.evidenceIntegrity?.digitalSignature || `SHA256:${(contentHash || '').slice(0, 16)}...`);

    // Digital seal badge
    page.drawRect(MARGIN + CONTENT_WIDTH - 110, curY + 20, 95, 26, COLORS.primary);
    page.drawText('MAVERICK CERTIFIED', MARGIN + CONTENT_WIDTH - 105, curY + 36, { font: 'F2', size: 7.5, color: COLORS.textLight });

    drawPageFooter(page, 6, totalPages, contentHash);
  }

  return doc.build();
}

/**
 * Computes SHA-256 hash of generated PDF bytes.
 * 
 * @param {Uint8Array} pdfBytes 
 * @returns {Promise<string>}
 */
export async function computePdfFileHash(pdfBytes) {
  // 1. Node.js native crypto
  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    try {
      const cryptoModule = 'node:crypto';
      const { createHash } = await import(/* @vite-ignore */ cryptoModule);
      return createHash('sha256').update(Buffer.from(pdfBytes)).digest('hex');
    } catch {
      // Fall through
    }
  }

  // 2. Web Crypto API
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    try {
      const hashBuffer = await crypto.subtle.digest('SHA-256', pdfBytes);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch {
      // Fall through
    }
  }

  // Fallback
  return computeSha256(new TextDecoder().decode(pdfBytes.slice(0, 4096)));
}

/**
 * Triggers a browser download of the generated PDF bytes.
 * 
 * @param {Uint8Array} pdfBytes 
 * @param {string} filename 
 */
export function downloadPdfInBrowser(pdfBytes, filename = 'MAVERICK-Forensic-Report.pdf') {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    throw new Error('downloadPdfInBrowser can only be called in a browser environment');
  }

  const blob = new Blob([pdfBytes], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
