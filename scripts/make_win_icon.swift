// Windows-Icon für SnitchBox: türkiser Schild mit drei farbigen Netz-Knoten (grün, rot, orange), freistehend ohne Kachel oder Rand.
// Jede Größe wird eigens gezeichnet (die kleinsten Größen mit nur einem Punkt statt des Netzes),
// damit das Motiv auch mit 16 px im Infobereich klar bleibt.
// Aufruf: xcrun swift make_win_icon.swift <Zielordner>  → icon_16.png … icon_256.png
import AppKit

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon"
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

// Füllung des Schilds: das helle Türkis der -Box-Kacheln (Vorgabe des Nutzers, Farbprobe #66CAD7 … #65C7E2).
let blueLight = CGColor(srgbRed: 0.43, green: 0.83, blue: 0.87, alpha: 1)
let blueDark = CGColor(srgbRed: 0.37, green: 0.75, blue: 0.89, alpha: 1)
let ink = CGColor(srgbRed: 0.07, green: 0.13, blue: 0.26, alpha: 1)

func render(_ size: Int) -> Data {
    let ss = 4 // Überabtastung
    let px = size * ss
    let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.scaleBy(x: CGFloat(px) / 256, y: CGFloat(px) / 256) // Zeichenfläche 256×256, y nach oben
    ctx.setLineCap(.round); ctx.setLineJoin(.round)
    let small = size <= 32
    // Mindestbreite in Zielpixeln, umgerechnet auf die 256er-Fläche.
    func w(_ units: CGFloat, minPx: CGFloat) -> CGFloat { max(units, minPx * 256 / CGFloat(size)) }

    // Schild: oben breite Kante mit leichter Wölbung, unten spitz zulaufend.
    let outline = w(12, minPx: 1.2)
    let inset = outline / 2 + 4
    let shield = CGMutablePath()
    shield.move(to: CGPoint(x: 128, y: 256 - inset))
    shield.addCurve(to: CGPoint(x: 256 - inset - 14, y: 204), control1: CGPoint(x: 160, y: 232), control2: CGPoint(x: 206, y: 212))
    shield.addCurve(to: CGPoint(x: 128, y: inset), control1: CGPoint(x: 256 - inset - 8, y: 96), control2: CGPoint(x: 192, y: 36))
    shield.addCurve(to: CGPoint(x: inset + 14, y: 204), control1: CGPoint(x: 64, y: 36), control2: CGPoint(x: inset + 8, y: 96))
    shield.addCurve(to: CGPoint(x: 128, y: 256 - inset), control1: CGPoint(x: 50, y: 212), control2: CGPoint(x: 96, y: 232))
    shield.closeSubpath()

    ctx.saveGState()
    ctx.addPath(shield); ctx.clip()
    let g = CGGradient(colorsSpace: nil, colors: [blueLight, blueDark] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(g, start: CGPoint(x: 128, y: 250), end: CGPoint(x: 128, y: 10), options: [])
    if !small {
        // Rechte Hälfte etwas dunkler: wirkt plastisch, ohne bei kleinen Größen zu verschmieren.
        ctx.setFillColor(CGColor(srgbRed: 0, green: 0.25, blue: 0.45, alpha: 0.12))
        ctx.fill(CGRect(x: 128, y: 0, width: 128, height: 256))
    }
    ctx.restoreGState()
    ctx.addPath(shield)
    ctx.setStrokeColor(ink)
    ctx.setLineWidth(outline)
    ctx.strokePath()

    let green = CGColor(srgbRed: 0.13, green: 0.66, blue: 0.26, alpha: 1)
    let red = CGColor(srgbRed: 0.90, green: 0.20, blue: 0.22, alpha: 1)
    let orange = CGColor(srgbRed: 0.98, green: 0.55, blue: 0.08, alpha: 1)
    // Farbiger Knoten mit dunklem Rand: auf dem hellen Schild klar zu erkennen (Weiß ging darauf unter).
    func node(_ c: CGPoint, _ r: CGFloat, _ color: CGColor) {
        let ring = w(7, minPx: 1)
        ctx.setFillColor(ink)
        ctx.fillEllipse(in: CGRect(x: c.x - r - ring, y: c.y - r - ring, width: 2 * (r + ring), height: 2 * (r + ring)))
        ctx.setFillColor(color)
        ctx.fillEllipse(in: CGRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r))
    }
    if size <= 20 {
        // Winzig: ein einzelner oranger Punkt.
        node(CGPoint(x: 128, y: 136), 40, orange)
    } else {
        // Netz aus drei Knoten: ein Programm (Mitte, orange = „wird gefragt“) und zwei Gegenstellen (grün erlaubt, rot verboten).
        let big = size >= 48
        let hub = CGPoint(x: 128, y: big ? 108 : 104), a = CGPoint(x: big ? 82 : 84, y: big ? 178 : 180), b = CGPoint(x: big ? 174 : 172, y: big ? 178 : 180)
        ctx.setStrokeColor(ink)
        ctx.setLineWidth(w(12, minPx: 1.6))
        for p in [a, b] { ctx.move(to: hub); ctx.addLine(to: p) }
        ctx.strokePath()
        node(a, big ? 23 : 26, green)
        node(b, big ? 23 : 26, red)
        node(hub, big ? 31 : 32, orange)
    }

    // Auf Zielgröße herunterrechnen.
    let big = ctx.makeImage()!
    let dst = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    dst.interpolationQuality = .high
    dst.draw(big, in: CGRect(x: 0, y: 0, width: size, height: size))
    let rep = NSBitmapImageRep(cgImage: dst.makeImage()!)
    return rep.representation(using: .png, properties: [:])!
}

for s in [16, 20, 24, 32, 40, 48, 64, 128, 256] {
    try! render(s).write(to: URL(fileURLWithPath: "\(out)/icon_\(s).png"))
}
