"""Builds docs/permission-form.pdf: the client permission form as a fillable PDF (type on screen,
tick boxes, or print and sign). Text follows docs/permission-form.md.

Usage:  py scripts/make_permission_form.py      (needs: py -m pip install reportlab)
"""
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph

VERSION = "0.10"
PAGES = [2]  # total pages, set by a first build
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "permission-form.pdf")

INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#475569")
ACCENT = colors.HexColor("#4F46E5")
ACCENT_SOFT = colors.HexColor("#EEF2FF")
LINE = colors.HexColor("#CBD5E1")
BOX = colors.HexColor("#94A3B8")
FIELD_BG = colors.HexColor("#F8FAFC")
WARN_BG = colors.HexColor("#FFFBEB")
WARN_LINE = colors.HexColor("#FDE68A")

W, H = letter
MARGIN = 54
CONTENT = W - 2 * MARGIN
BOTTOM = 64

BODY = ParagraphStyle("body", fontName="Helvetica", fontSize=9.6, leading=13.2, textColor=INK, alignment=TA_LEFT)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8.4, leading=11.2, textColor=MUTED)
BULLET = ParagraphStyle("bullet", parent=BODY, leftIndent=12, bulletIndent=2, bulletColor=ACCENT)


class Form:
    def __init__(self, path):
        self.c = canvas.Canvas(path, pagesize=letter)
        self.c.setTitle("Permission for a Website Safety Check-up")
        self.c.setAuthor("Exposure Scanner")
        self.c.setSubject("Client permission form for a read-only website and code safety check-up")
        self.c.setCreator("Exposure Scanner (scripts/make_permission_form.py)")
        self.page = 1
        self.section_no = 0
        self.y = H - MARGIN
        self.header()

    # ------------------------------------------------------------- page furniture
    def header(self):
        c = self.c
        if self.page == 1:
            c.setFillColor(INK)
            c.rect(0, H - 118, W, 118, stroke=0, fill=1)
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 20)
            c.drawString(MARGIN, H - 62, "Permission for a Website Safety Check-up")
            c.setFillColor(colors.HexColor("#C7D2FE"))
            c.setFont("Helvetica", 10)
            c.drawString(MARGIN, H - 82, "A read-only check of websites and code. Fill it in on screen, or print it and sign by hand.")
            self.y = H - 140
        else:
            c.setFillColor(MUTED)
            c.setFont("Helvetica", 8.5)
            c.drawString(MARGIN, H - 36, "Permission for a Website Safety Check-up (continued)")
            c.setStrokeColor(LINE)
            c.setLineWidth(0.6)
            c.line(MARGIN, H - 44, W - MARGIN, H - 44)
            self.y = H - 66

    def footer(self):
        c = self.c
        c.setStrokeColor(LINE)
        c.setLineWidth(0.6)
        c.line(MARGIN, 42, W - MARGIN, 42)
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 7.8)
        c.drawString(MARGIN, 30, "Plain-language template, not legal advice. Form version %s. Made with Exposure Scanner "
                                 "(free, open source)." % VERSION)
        c.drawRightString(W - MARGIN, 30, "Page %d of %d" % (self.page, PAGES[0]))

    def new_page(self):
        self.footer()
        self.c.showPage()
        self.page += 1
        self.header()

    def need(self, h):
        if self.y - h < BOTTOM:
            self.new_page()

    # ------------------------------------------------------------- text
    def para(self, text, style=BODY, x=MARGIN, width=CONTENT, gap=6, bullet=None):
        p = Paragraph(text, style, bulletText=bullet)
        _, h = p.wrap(width, 1000)
        self.need(h + gap)
        p.drawOn(self.c, x, self.y - h)
        self.y -= h + gap
        return h

    def bullets(self, items):
        for t in items:
            self.para(t.replace("&bull; ", "", 1), BULLET, gap=3, bullet="•")
        self.y -= 4

    def section(self, title, keep=60):
        self.need(keep + 30)
        self.section_no += 1
        c = self.c
        self.y -= 6
        c.setFillColor(ACCENT_SOFT)
        c.circle(MARGIN + 9, self.y - 7, 9, stroke=0, fill=1)
        c.setFillColor(ACCENT)
        c.setFont("Helvetica-Bold", 9.5)
        c.drawCentredString(MARGIN + 9, self.y - 10.4, str(self.section_no))
        c.setFillColor(INK)
        c.setFont("Helvetica-Bold", 12.5)
        c.drawString(MARGIN + 26, self.y - 11.5, title)
        self.y -= 26

    # ------------------------------------------------------------- fields
    def label(self, text, x, y):
        self.c.setFillColor(MUTED)
        self.c.setFont("Helvetica", 8.2)
        self.c.drawString(x, y, text)

    def text_field(self, name, label, x, y, w, h=20, multiline=False, tooltip=None):
        """label above a box whose top edge is at y; returns the box bottom"""
        self.label(label, x, y)
        top = y - 4
        self.c.setFillColor(FIELD_BG)
        self.c.setStrokeColor(BOX)
        self.c.setLineWidth(0.7)
        self.c.roundRect(x, top - h, w, h, 2.5, stroke=1, fill=1)
        self.c.acroForm.textfield(
            name=name, tooltip=tooltip or label, x=x + 1, y=top - h + 1, width=w - 2, height=h - 2,
            fontName="Helvetica", fontSize=10, borderWidth=0, fillColor=None, borderColor=None,
            textColor=INK, fieldFlags="multiline" if multiline else "")
        return top - h

    def checkbox(self, name, text, x=MARGIN, width=CONTENT, tooltip=None):
        p = Paragraph(text, BODY)
        _, h = p.wrap(width - 22, 1000)
        self.need(h + 8)
        self.c.setFillColor(colors.white)
        self.c.setStrokeColor(ACCENT)
        self.c.setLineWidth(1)
        self.c.roundRect(x, self.y - 12, 12, 12, 2, stroke=1, fill=1)
        self.c.acroForm.checkbox(
            name=name, tooltip=tooltip or name, x=x, y=self.y - 12, size=12, buttonStyle="check",
            borderWidth=0, borderColor=None, fillColor=None, textColor=ACCENT)
        p.drawOn(self.c, x + 20, self.y - h)
        self.y -= max(h, 13) + 7

    def radio(self, group, value, x, y, tooltip):
        self.c.acroForm.radio(
            name=group, value=value, tooltip=tooltip, selected=False, x=x, y=y, size=12,
            buttonStyle="circle", borderWidth=0.8, borderColor=ACCENT, fillColor=colors.white,
            textColor=ACCENT, forceBorder=True)

    def save(self):
        self.footer()
        self.c.save()


def build(path):
    f = Form(path)
    c = f.c

    f.para("By signing this form, the client allows the checker to run a <b>read-only</b> safety check-up of the "
           "websites and code listed in section 2, and nothing else. Both sides sign before the check-up starts.")
    f.y -= 4

    # 1. parties
    f.section("Who this is between", keep=130)
    f.y -= 4
    col = (CONTENT - 24) / 2
    xl, xr = MARGIN, MARGIN + col + 24
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(xl, f.y, "Client")
    c.drawString(xr, f.y, "Checker")
    f.y -= 18
    for key, label in (("name", "Full name"), ("business", "Business name"), ("email", "Email"), ("phone", "Phone")):
        b1 = f.text_field("client_" + key, label, xl, f.y, col, tooltip="Client: " + label)
        f.text_field("checker_" + key, label, xr, f.y, col, tooltip="Checker: " + label)
        f.y = b1 - 12

    # 2. scope
    f.section("What will be checked", keep=200)
    f.para("Only the items written here are checked. Anything not listed is out of bounds.", SMALL, gap=12)
    wa = CONTENT * 0.56
    wb = CONTENT - wa - 12
    for i in range(1, 6):
        lab_a = "Website address %d (for example shop.com)" % i if i == 1 else "Website address %d" % i
        lab_b = "Who hosts or manages it (hosting company, web designer)" if i == 1 else "Who hosts or manages it"
        b1 = f.text_field("site_%d" % i, lab_a, MARGIN, f.y, wa, h=19, tooltip="Website address %d" % i)
        f.text_field("site_%d_host" % i, lab_b, MARGIN + wa + 12, f.y, wb, h=19, tooltip="Host of website %d" % i)
        f.y = b1 - 9
    f.y -= 2
    f.checkbox("code_folder", "Also check this code folder or repository for leaked passwords and keys:",
               tooltip="Also check a code folder or repository")
    f.y = f.text_field("code_folder_where", "Folder or repository (for example github.com/shop/website)", MARGIN + 20,
                       f.y + 2, CONTENT - 20, h=19) - 10

    # 3. what it does
    f.section("What the check-up does", keep=40)
    f.para("The check-up only reads what each website already shows to every visitor. For each website, the checker:")
    f.bullets([
        "&bull; Makes one normal page request, the same as opening the home page in a browser.",
        "&bull; When it is needed to read a software version, opens up to five more public files that any visitor's "
        "browser could open, such as the site's news feed or its main script file.",
        "&bull; Makes one secure-connection check, the same step a browser takes before it shows the padlock.",
        "&bull; Reads the security settings the site sends with its pages, its certificate, and which software runs "
        "it (for example WordPress and its version, the web server and its operating system), and compares those "
        "versions with public lists of known security problems and of versions that no longer get updates.",
        "&bull; Reads the domain's public email records (SPF, DMARC and DKIM) to see whether scammers could send "
        "email in the business's name. No email is sent.",
    ])
    f.para("For a code folder or repository, the checker looks for passwords, keys and tokens that should not be "
           "there, and for software packages with known harmful versions. The client receives a written report in "
           "plain language: what was found, why it matters and how to fix it.")

    # 4. never
    f.section("What the check-up will never do", keep=110)
    f.bullets([
        "&bull; Log in to anything, or guess passwords.",
        "&bull; Try to break in, or use any weakness it finds.",
        "&bull; Send heavy traffic or load tests. The website will not slow down.",
        "&bull; Change anything on the website, server, accounts or code.",
        "&bull; Open private pages, admin areas or customer data, or check anything not listed in section 2.",
    ])

    # 5. confirmation
    f.section("Client confirmation", keep=90)
    f.checkbox("confirm_owner", "I own every website and code folder listed in section 2, or I have the right to "
               "allow this check-up for them.", tooltip="Client confirms ownership or the right to allow the check-up")
    f.checkbox("confirm_host", "If a hosting company, web designer or agency manages a listed website, I am allowed "
               "to request this check-up under my agreement with them.", tooltip="Client confirms the host agreement allows it")
    f.checkbox("confirm_readonly", "I understand the check-up only reads what the websites show to any visitor, as "
               "described in section 3.", tooltip="Client understands the check-up is read-only")

    # 6. when and fee
    f.section("When it happens, and the fee", keep=150)
    f.y = f.text_field("dates", "Check-up date or dates", MARGIN, f.y, CONTENT * 0.5) - 14
    f.label("The client chooses one option:", MARGIN, f.y)
    f.y -= 22
    for value, text, price_label in (("one_time", "One-time check-up", "Price"),
                                     ("monthly", "Monthly re-check, cancel any time", "Price per month")):
        f.radio("plan", value, MARGIN, f.y - 2, text)
        c.setFillColor(INK)
        c.setFont("Helvetica", 9.6)
        c.drawString(MARGIN + 20, f.y + 1, text)
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 8.2)
        c.drawRightString(MARGIN + 318, f.y + 1, price_label)
        c.setFillColor(FIELD_BG)
        c.setStrokeColor(BOX)
        c.setLineWidth(0.7)
        c.roundRect(MARGIN + 326, f.y - 6, 130, 19, 2.5, stroke=1, fill=1)
        c.acroForm.textfield(name="price_" + value, tooltip=text + ": " + price_label, x=MARGIN + 327,
                             y=f.y - 5, width=128, height=17, fontName="Helvetica", fontSize=10, borderWidth=0,
                             fillColor=None, borderColor=None, textColor=INK)
        f.y -= 28
    f.y = f.text_field("payment_due", "Payment is due", MARGIN, f.y + 4, CONTENT * 0.5) - 12
    f.bullets([
        "&bull; Permission covers only the dates above, or each month until cancelled with monthly re-checks.",
        "&bull; The checker tells the client before starting and again when finished. A serious problem is reported "
        "right away instead of waiting for the report.",
        "&bull; The client can withdraw permission at any time by email or message. The checker stops as soon as they "
        "receive it.",
    ])

    # 7. results
    f.section("Who receives the results", keep=120)
    f.para("The results belong to the client and go only to the people named here.", SMALL, gap=12)
    f.y = f.text_field("recipients", "Names and email addresses", MARGIN, f.y, CONTENT, h=40, multiline=True) - 12
    b1 = f.text_field("urgent_name", "Contact for an urgent problem: name", MARGIN, f.y, CONTENT * 0.5 - 6)
    f.text_field("urgent_phone", "Phone", MARGIN + CONTENT * 0.5 + 6, f.y, CONTENT * 0.5 - 6)
    f.y = b1 - 12
    f.bullets([
        "&bull; The checker never shares, publishes or shows the results to anyone else without the client's written "
        "permission.",
        "&bull; If a password or key is found, the report shows only where it is and a masked hint, such as ****MPLE. "
        "The full value is never copied. The client should change any key that is found.",
        "&bull; Any copy of the client's code is deleted as soon as the check-up is finished. Results are deleted 30 "
        "days after the report is delivered; with monthly re-checks the latest results are kept to compare months.",
    ])

    # 8. limits
    f.section("Limits", keep=90)
    f.bullets([
        "&bull; A clean report means no problems were found in the checks above. It does not mean the website is "
        "fully secure.",
        "&bull; Software versions are read from what the website shows, which can be hidden or wrong. Versions worked "
        "out from hints are marked \"estimated\", so the client can confirm them in the site's admin area.",
        "&bull; The checker gives advice. The client, or the client's web developer, decides what to change and makes "
        "the changes. The checker's total responsibility is limited to the fee paid for the check-up.",
    ])

    # 9. signatures
    f.section("Signatures", keep=150)
    f.para("By signing, both sides agree to everything on this form. Sign by typing your full name, or print the "
           "form and sign by hand.", SMALL, gap=14)
    for who in ("client", "checker"):
        c.setFillColor(INK)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(MARGIN, f.y - 2, "Client" if who == "client" else "Checker")
        f.y -= 14
        w1 = CONTENT * 0.36
        w2 = CONTENT * 0.40
        w3 = CONTENT - w1 - w2 - 24
        b = f.text_field(who + "_sign_name", "Name", MARGIN, f.y, w1, h=22)
        f.text_field(who + "_signature", "Signature", MARGIN + w1 + 12, f.y, w2, h=22,
                     tooltip=("Client" if who == "client" else "Checker") + " signature")
        f.text_field(who + "_date", "Date", MARGIN + w1 + w2 + 24, f.y, w3, h=22)
        f.y = b - 16

    f.save()
    return f.page


if __name__ == "__main__":
    PAGES[0] = build(OUT)  # first pass counts the pages for the footer
    build(OUT)
    print("written", os.path.normpath(OUT), "-", PAGES[0], "pages")
