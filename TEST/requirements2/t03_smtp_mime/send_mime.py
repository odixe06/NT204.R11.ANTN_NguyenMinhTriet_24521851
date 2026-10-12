import smtplib

B64_MSG = (
    "From: alice@test.local\r\n"
    "To: bob@test.local\r\n"
    "Subject: t03 base64\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "WGluIGNow6BvLCDEkcOieSBsw6AgdGjGsCB0aOG7rSBuZ2hp4buHbSBUMDMgQmFzZTY0Lg==\r\n"
)

QP_MSG = (
    "From: alice@test.local\r\n"
    "To: bob@test.local\r\n"
    "Subject: t03 quoted-printable\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Content-Transfer-Encoding: quoted-printable\r\n"
    "\r\n"
    "Gi=C3=A1 tr=E1=BB=8B: 1+1=3D2, d=C3=B2ng n=C3=A0y r=E1=BA=A5t d=C3=A0i n=C3=\r\n"
    "=AAn =C4=91=C6=B0=E1=BB=A3c ng=E1=BA=AFt b=E1=BA=B1ng soft line break c=E1=\r\n"
    "=BB=A7a Quoted-Printable.\r\n"
)

with smtplib.SMTP("127.0.0.1", 25) as s:
    s.ehlo()
    s.sendmail("alice@test.local", ["bob@test.local"], B64_MSG)
    s.sendmail("alice@test.local", ["bob@test.local"], QP_MSG)