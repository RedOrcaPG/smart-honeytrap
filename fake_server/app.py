# ==========================================================
# Import Standard Library
# ==========================================================

from datetime import datetime

# ==========================================================
# Import Third Party Library
# ==========================================================

from flask import (
    Flask,
    request,
    g,
    render_template,
    redirect,
    url_for
)

# ==========================================================
# Import Local Module
# ==========================================================

from config import SERVER_CONFIG, LOGGER_CONFIG
from logger.logger import Logger
from logger.logger import LogEntry


# ==========================================================
# Flask Application
# ==========================================================

app = Flask(__name__)

logger = Logger()


@app.before_request
def before_request():

    g.log_entry = LogEntry()
    g.log_entry.timestamp = datetime.now()
    g.log_entry.src_ip = request.remote_addr
    g.log_entry.dst_ip = request.host.split(":")[0]
    g.log_entry.dst_port = int(request.environ.get("SERVER_PORT", 0))
    g.log_entry.protocol = request.scheme.upper()
    g.log_entry.method = request.method
    g.log_entry.url = request.path
    g.log_entry.request_size = request.content_length or 0
    g.log_entry.packet_rate = 0
    g.log_entry.byte_rate = 0
    g.log_entry.detection_score = 0
    g.log_entry.decision = "NORMAL"
    g.log_entry.redirected = False
    g.log_entry.user_agent = request.headers.get("User-Agent", "-")


@app.route("/", methods=["GET", "POST"])

@app.route("/login", methods=["GET", "POST"])
def login():

    error = ""
    username = ""

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # TODO
        # Logger nanti sudah otomatis mencatat request
        # Semua login dianggap berhasil
        return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        error=error,
        username=username
    )

@app.route("/dashboard")
def dashboard():

    statistics = {
        "total_mahasiswa": 523,
        "total_mk": 35,
        "total_nilai": 2410
    }

    students = [

        {
            "id": 1,
            "nim": "2210101001",
            "nama": "Andi Saputra",
            "program_studi": "Teknik Informatika"
        },

        {
            "id": 2,
            "nim": "2210101002",
            "nama": "Budi Santoso",
            "program_studi": "Sistem Informasi"
        },

        {
            "id": 3,
            "nim": "2210101003",
            "nama": "Siti Aisyah",
            "program_studi": "Teknik Informatika"
        }

    ]

    return render_template(
        "dashboard.html",
        statistics=statistics,
        students=students
    )

@app.route("/student/<nim>")
def student_detail(nim):

    students = {

        "2210101001": {

            "nama": "Andi Saputra",
            "program_studi": "Teknik Informatika",
            "angkatan": 2022,
            "status": "Aktif",
            "ipk": 3.82,
            "courses": [

                {
                    "nama": "Algoritma",
                    "nilai": "A"
                },

                {
                    "nama": "Pemrograman Dasar",
                    "nilai": "A"
                },

                {
                    "nama": "Inofasi Digital",
                    "nilai": "A"
                },

                {
                    "nama": "Statistika",
                    "nilai": "A"
                },

                {
                    "nama": "Bahasa Inggris",
                    "nilai": "A"
                },
            ]
        },

        "2210101002": {

            "nama": "Budi Santoso",
            "program_studi": "Teknik Informatika",
            "angkatan": 2022,
            "status": "Aktif",
            "ipk": 3.80,
            "courses": [

                {
                    "nama": "Algoritma",
                    "nilai": "A"
                },

                {
                    "nama": "Pemrograman Dasar",
                    "nilai": "B"
                },

                {
                    "nama": "Inofasi Digital",
                    "nilai": "A"
                },

                {
                    "nama": "Statistika",
                    "nilai": "A"
                },

                {
                    "nama": "Bahasa Inggris",
                    "nilai": "-A"
                },
            ]
        },

                "2210101003": {

            "nama": "Siti Aisyah",
            "program_studi": "Teknik Informatika",
            "angkatan": 2022,
            "status": "Aktif",
            "ipk": 3.81,
            "courses": [

                {
                    "nama": "Algoritma",
                    "nilai": "A"
                },

                {
                    "nama": "Pemrograman Dasar",
                    "nilai": "B+"
                },

                {
                    "nama": "Inofasi Digital",
                    "nilai": "A"
                },

                {
                    "nama": "Statistika",
                    "nilai": "A"
                },

                {
                    "nama": "Bahasa Inggris",
                    "nilai": "A-"
                },
            ]
        }
    }

    mhs_data = students.get(nim)
    return render_template(
        "student_detail.html",
        nim=nim,
        mhs=mhs_data
    )


@app.after_request
def after_request(response):
    if not any(
        request.path.startswith(path)
        for path in LOGGER_CONFIG["ignore_paths"]
    ):
        g.log_entry.status_code = response.status_code
        logger.save_http(g.log_entry)
    return response


def start_server():

    app.run(
        host=SERVER_CONFIG["host"],
        port=SERVER_CONFIG["port"],
        debug=SERVER_CONFIG["debug"]
    )


if __name__ == "__main__":

    start_server()