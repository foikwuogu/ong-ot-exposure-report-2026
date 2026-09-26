// Shared document helpers (docx-js). US Letter, Arial, built-in heading styles.
// Every report module passes only strings built from stats.json; nothing here holds a number.
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell,
  WidthType, ShadingType, BorderStyle, ImageRun, Header, Footer, PageNumber, LevelFormat,
  ExternalHyperlink, PageBreak, TableOfContents,
} = require("docx");

const FONT = "Arial";
const INK = "1A1A1A", INK2 = "52514E", RULE = "D9D8D3", HEAD_FILL = "EEF3FA", ACCENT = "1C5CAB";
const CONTENT_W = 9360; // 6.5in in DXA

function runs(text, base = {}) {
  // light inline markup: **bold**, _italic_
  const out = [];
  const re = /(\*\*[^*]+\*\*|(?<![\w\/.])_[^_\s][^_]*_(?![\w\/]))/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(new TextRun({ text: text.slice(last, m.index), ...base }));
    const t = m[0];
    if (t.startsWith("**")) out.push(new TextRun({ text: t.slice(2, -2), bold: true, ...base }));
    else out.push(new TextRun({ text: t.slice(1, -1), italics: true, ...base }));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(new TextRun({ text: text.slice(last), ...base }));
  return out;
}

const P = (text, opts = {}) => new Paragraph({ children: runs(text, opts.run || {}), spacing: { after: 140, line: 288 }, alignment: opts.align, ...(opts.para || {}) });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)], spacing: { before: 320, after: 140 } });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)], spacing: { before: 240, after: 100 } });
const BUL = (t, level = 0) => new Paragraph({ numbering: { reference: "bullets", level }, children: runs(t), spacing: { after: 80, line: 276 } });
// each numbered list gets its own instance so numbering restarts at 1
const NUMi = (inst) => (t) => new Paragraph({ numbering: { reference: "numbers", level: 0, instance: inst }, children: runs(t), spacing: { after: 80, line: 276 } });
const NUM = NUMi(0), NUM1 = NUMi(1), NUM2 = NUMi(2), NUM3 = NUMi(3), NUM4 = NUMi(4), NUM5 = NUMi(5);
const PB = () => new Paragraph({ children: [new PageBreak()] });
const CAP = (t) => new Paragraph({ children: runs(t, { size: 17, color: INK2 }), spacing: { before: 60, after: 220 } });
const LINK = (text, url) => new Paragraph({ children: [new ExternalHyperlink({ link: url, children: [new TextRun({ text, style: "Hyperlink" })] })], spacing: { after: 80 } });

function pngSize(file) {
  const b = fs.readFileSync(file);
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
}

function FIG(file, caption, widthIn = 6.5) {
  const { w, h } = pngSize(file);
  const W = Math.round(widthIn * 96), H = Math.round(W * h / w);
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 40 },
      children: [new ImageRun({ type: "png", data: fs.readFileSync(file), transformation: { width: W, height: H },
        altText: { title: path.basename(file), description: caption, name: path.basename(file) } })] }),
    CAP(caption),
  ];
}

function TABLE(header, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  const border = { style: BorderStyle.SINGLE, size: 4, color: RULE };
  const borders = { top: border, bottom: border, left: border, right: border };
  const cell = (t, i, head) => new TableCell({
    borders, width: { size: widths[i], type: WidthType.DXA },
    shading: head ? { fill: HEAD_FILL, type: ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 60, bottom: 60, left: 100, right: 100 },
    children: [new Paragraph({ alignment: /^[\s\d.,%+\-n\/a]+$/.test(String(t)) && i > 0 ? AlignmentType.RIGHT : AlignmentType.LEFT,
      children: runs(String(t), { size: 17, bold: head, color: INK }) })],
  });
  return new Table({
    width: { size: total, type: WidthType.DXA }, columnWidths: widths,
    rows: [new TableRow({ tableHeader: true, children: header.map((h, i) => cell(h, i, true)) }),
      ...rows.map((r) => new TableRow({ children: r.map((c, i) => cell(c, i, false)) }))],
  });
}

function BANNER(text) {
  return new Paragraph({
    children: [new TextRun({ text, bold: true, color: "8A1C1C", size: 18 })],
    shading: { type: ShadingType.CLEAR, fill: "FBEAEA", color: "auto" },
    border: { left: { style: BorderStyle.SINGLE, size: 18, color: "C0392B", space: 6 } },
    spacing: { before: 120, after: 200 },
  });
}

function RULEPARA() {
  return new Paragraph({ border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: RULE, space: 1 } }, spacing: { after: 200 } });
}

function build({ outFile, children, draft, runningTitle }) {
  const doc = new Document({
    creator: "", title: runningTitle,
    styles: {
      default: { document: { run: { font: FONT, size: 20, color: INK } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 28, bold: true, font: FONT, color: ACCENT }, paragraph: { spacing: { before: 320, after: 140 }, outlineLevel: 0 } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 23, bold: true, font: FONT, color: INK }, paragraph: { spacing: { before: 240, after: 100 }, outlineLevel: 1 } },
      ],
    },
    numbering: { config: [
      { reference: "bullets", levels: [
        { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } },
        { level: 1, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1080, hanging: 270 } } } }] },
      { reference: "numbers", levels: [
        { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 360 } } } }] },
    ] },
    sections: [{
      properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1300, right: 1440, bottom: 1300, left: 1440 } } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT,
        children: [new TextRun({ text: (draft ? "DRAFT — not for citation — " : "") + runningTitle, size: 15, color: draft ? "8A1C1C" : INK2 })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ children: [PageNumber.CURRENT], size: 16, color: INK2 })] })] }) },
      children,
    }],
  });
  return Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(outFile, buf); return outFile; });
}

module.exports = { P, H1, H2, BUL, NUM, NUM1, NUM2, NUM3, NUM4, NUM5, PB, CAP, LINK, FIG, TABLE, BANNER, RULEPARA, build, runs, TextRun, Paragraph, AlignmentType, CONTENT_W, INK2, TableOfContents };
