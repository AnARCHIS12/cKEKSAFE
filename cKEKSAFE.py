from datetime import datetime
from pathlib import Path
import json
import os
import sys
import threading
import time

import customtkinter as ctk
import requests
from tkinter import BooleanVar, Label, PhotoImage, filedialog, messagebox


SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"
SCAN_MAX_ATTEMPTS = 4
REPORT_MAX_ATTEMPTS = 12
REPORT_POLL_INTERVAL_SECONDS = 10
RATE_LIMIT_STATUS_CODE = 204
RATE_LIMIT_WAIT_SECONDS = 65
REQUEST_TIMEOUT_SECONDS = 60
CONFIG_PATH = Path.home() / ".config" / "ckeksafe" / "settings.json"
REPORTS_FOLDER_NAME = "cKEKSAFE-Rapports"
APP_DIR = Path(__file__).resolve().parent
LOGO_PNG = "assets/logo-red-black.png"
LOGO_ICO = "assets/logo-red-black.ico"
LOGO_SIDEBAR = "assets/logo-red-black-sidebar.png"

COLORS = {
    "bg": ("#17080a", "#050505"),
    "sidebar": ("#21090d", "#090909"),
    "panel": ("#260d12", "#111111"),
    "card": ("#351016", "#181010"),
    "input": ("#13080a", "#0b0b0b"),
    "input_border": ("#7f1d1d", "#7f1d1d"),
    "primary_text": ("#fff7f7", "#fff7f7"),
    "secondary_text": ("#fca5a5", "#fca5a5"),
    "label_text": ("#fecaca", "#fecaca"),
    "textbox_text": ("#ffe4e6", "#ffe4e6"),
    "soft_button": ("#3a1116", "#231013"),
    "soft_button_hover": ("#57151c", "#3a1116"),
    "soft_button_text": ("#ffe4e6", "#ffe4e6"),
    "scrollbar": ("#7f1d1d", "#7f1d1d"),
    "scrollbar_hover": ("#b91c1c", "#b91c1c"),
    "error_card": ("#450a0a", "#270909"),
    "error_title": ("#fecaca", "#fecaca"),
    "error_text": ("#fca5a5", "#fca5a5"),
    "link": ("#f87171", "#f87171"),
    "accent": "#dc2626",
    "accent_hover": "#b91c1c",
    "accent_text": "#fff7f7",
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")
ctk.set_widget_scaling(0.92)


def resource_path(relative_path):
    base_path = Path(getattr(sys, "_MEIPASS", APP_DIR))
    return base_path / relative_path


def default_documents_dir():
    if os.name == "nt":
        return Path.home() / "Documents"

    xdg_documents_dir = read_xdg_user_dir("XDG_DOCUMENTS_DIR")
    if xdg_documents_dir is not None:
        return xdg_documents_dir

    return Path.home() / "Documents"


def read_xdg_user_dir(key):
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    user_dirs_path = config_home / "user-dirs.dirs"

    try:
        lines = user_dirs_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    prefix = f"{key}="
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line.startswith(prefix):
            continue

        value = stripped_line[len(prefix) :].strip().strip('"')
        if not value:
            return None

        expanded_value = value.replace("$HOME", str(Path.home())).replace("${HOME}", str(Path.home()))
        return Path(os.path.expandvars(os.path.expanduser(expanded_value)))

    return None


class SafeScrollableFrame(ctk.CTkScrollableFrame):
    def check_if_master_is_canvas(self, widget):
        if isinstance(widget, str):
            try:
                widget = self._parent_canvas.nametowidget(widget)
            except (KeyError, AttributeError):
                return False

        if widget == self._parent_canvas:
            return True

        master = getattr(widget, "master", None)
        if master is not None:
            return self.check_if_master_is_canvas(master)

        return False


class CkekSafeApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.files = []
        self.is_scanning = False
        self.malicious_found = False
        self.remember_api_var = BooleanVar(value=False)
        self.logo_image = None
        self.window_icon = None

        self.title("cKEKSAFE")
        self._set_window_icon()
        self.geometry("920x640")
        self.minsize(760, 560)
        self.configure(fg_color=COLORS["bg"])

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_panel()
        self._load_saved_api_key()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color=COLORS["sidebar"])
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(7, weight=1)
        sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(24, 16))

        logo_loaded = self._add_sidebar_logo(brand)

        if not logo_loaded:
            ctk.CTkLabel(
                brand,
                text="cKEKSAFE",
                font=ctk.CTkFont(size=28, weight="bold"),
                text_color=COLORS["primary_text"],
            ).pack(anchor="w")
        ctk.CTkLabel(
            brand,
            text="Analyse VirusTotal rapide et lisible",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["secondary_text"],
        ).pack(anchor="w", pady=(4, 0))

        ctk.CTkLabel(
            sidebar,
            text="Cle API VirusTotal",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["label_text"],
        ).grid(row=1, column=0, sticky="w", padx=18, pady=(16, 6))

        self.api_key_entry = ctk.CTkEntry(
            sidebar,
            height=42,
            show="*",
            placeholder_text="Colle ta cle API ici",
            border_color=COLORS["input_border"],
            fg_color=COLORS["input"],
            text_color=COLORS["primary_text"],
            placeholder_text_color=COLORS["secondary_text"],
        )
        self.api_key_entry.grid(row=2, column=0, sticky="ew", padx=18)

        self.remember_api_checkbox = ctk.CTkCheckBox(
            sidebar,
            text="Memoriser la cle API",
            variable=self.remember_api_var,
            command=self._on_remember_api_changed,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["input_border"],
            checkmark_color=COLORS["accent_text"],
            text_color=COLORS["label_text"],
        )
        self.remember_api_checkbox.grid(row=3, column=0, sticky="w", padx=18, pady=(12, 0))

        actions = ctk.CTkFrame(sidebar, fg_color="transparent")
        actions.grid(row=4, column=0, sticky="ew", padx=18, pady=(20, 8))
        actions.grid_columnconfigure((0, 1), weight=1)

        self.select_button = ctk.CTkButton(
            actions,
            text="Ajouter",
            height=42,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            command=self.select_files,
        )
        self.select_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self.clear_button = ctk.CTkButton(
            actions,
            text="Vider",
            height=42,
            fg_color=COLORS["soft_button"],
            hover_color=COLORS["soft_button_hover"],
            text_color=COLORS["soft_button_text"],
            command=self.clear_files,
        )
        self.clear_button.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.scan_button = ctk.CTkButton(
            sidebar,
            text="Lancer l'analyse",
            height=48,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            command=self.check_files,
        )
        self.scan_button.grid(row=5, column=0, sticky="ew", padx=18, pady=(14, 18))

        self.progress = ctk.CTkProgressBar(sidebar, height=12, progress_color=COLORS["accent"])
        self.progress.grid(row=6, column=0, sticky="ew", padx=18)
        self.progress.set(0)

        stats = ctk.CTkFrame(sidebar, fg_color=COLORS["card"], corner_radius=8)
        stats.grid(row=7, column=0, sticky="new", padx=18, pady=20)
        stats.grid_columnconfigure(0, weight=1)

        self.files_count_label = self._stat_label(stats, "0", "fichiers")
        self.files_count_label.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        self.threat_count_label = self._stat_label(stats, "0", "alertes")
        self.threat_count_label.grid(row=1, column=0, sticky="ew", padx=12, pady=(6, 12))

        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.grid(row=8, column=0, sticky="ew", padx=18, pady=(0, 18))
        ctk.CTkLabel(
            footer,
            text="Mode",
            text_color=COLORS["secondary_text"],
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w")
        self.appearance_menu = ctk.CTkSegmentedButton(
            footer,
            values=["Sombre", "Clair", "Systeme"],
            command=self.set_appearance,
            fg_color=COLORS["input"],
            selected_color=COLORS["accent"],
            selected_hover_color=COLORS["accent_hover"],
            unselected_color=COLORS["soft_button"],
            unselected_hover_color=COLORS["soft_button_hover"],
            text_color=COLORS["accent_text"],
        )
        self.appearance_menu.pack(fill="x", pady=(8, 0))
        self.appearance_menu.set("Sombre")

    def _set_window_icon(self):
        logo_png = resource_path(LOGO_PNG)
        logo_ico = resource_path(LOGO_ICO)

        try:
            if logo_png.exists():
                self.window_icon = PhotoImage(file=str(logo_png))
                self.iconphoto(True, self.window_icon)
        except Exception:
            pass

        try:
            if logo_ico.exists():
                self.iconbitmap(str(logo_ico))
        except Exception:
            pass

    def _add_sidebar_logo(self, parent):
        logo_path = resource_path(LOGO_SIDEBAR)
        if not logo_path.exists():
            return False

        try:
            self.logo_image = PhotoImage(file=str(logo_path))
            Label(
                parent,
                image=self.logo_image,
                bg="#090909",
                borderwidth=0,
                highlightthickness=0,
            ).pack(anchor="w", pady=(0, 12))
        except Exception:
            return False

        return True

    def _stat_label(self, parent, value, title):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkLabel(
            frame,
            text=value,
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLORS["primary_text"],
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            frame,
            text=title,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["secondary_text"],
        ).grid(row=0, column=1, sticky="e")
        return frame

    def _build_main_panel(self):
        main = ctk.CTkFrame(self, corner_radius=0, fg_color=COLORS["bg"])
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(22, 14))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="Tableau d'analyse",
            font=ctk.CTkFont(size=25, weight="bold"),
            text_color=COLORS["primary_text"],
        ).grid(row=0, column=0, sticky="w")
        self.status_label = ctk.CTkLabel(
            header,
            text="Pret a analyser",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["secondary_text"],
        )
        self.status_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

        self.file_textbox = ctk.CTkTextbox(
            main,
            height=126,
            border_width=1,
            border_color=COLORS["input_border"],
            fg_color=COLORS["panel"],
            text_color=COLORS["textbox_text"],
            corner_radius=8,
            font=ctk.CTkFont(size=13),
        )
        self.file_textbox.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 14))
        self.file_textbox.insert("1.0", "Aucun fichier selectionne.")
        self.file_textbox.configure(state="disabled")

        results_shell = ctk.CTkFrame(main, fg_color=COLORS["panel"], corner_radius=8)
        results_shell.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        results_shell.grid_columnconfigure(0, weight=1)
        results_shell.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            results_shell,
            text="Resultats",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["primary_text"],
        ).grid(row=0, column=0, sticky="w", padx=18, pady=(16, 8))

        self.results_frame = SafeScrollableFrame(
            results_shell,
            fg_color="transparent",
            scrollbar_button_color=COLORS["scrollbar"],
            scrollbar_button_hover_color=COLORS["scrollbar_hover"],
        )
        self.results_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._show_empty_results()

    def select_files(self):
        selected_paths = filedialog.askopenfilenames(title="Selectionner des fichiers")
        if not selected_paths:
            return

        known_paths = set(self.files)
        for path in selected_paths:
            if path not in known_paths:
                self.files.append(path)
                known_paths.add(path)

        self._refresh_file_list()

    def clear_files(self):
        if self.is_scanning:
            return

        self.files.clear()
        self._refresh_file_list()
        self._clear_results()
        self._show_empty_results()
        self.progress.set(0)
        self.status_label.configure(text="Pret a analyser")
        self._set_stat_value(self.threat_count_label, "0")

    def _refresh_file_list(self):
        self.file_textbox.configure(state="normal")
        self.file_textbox.delete("1.0", "end")

        if self.files:
            text = "\n".join(f"{index + 1}. {path}" for index, path in enumerate(self.files))
        else:
            text = "Aucun fichier selectionne."

        self.file_textbox.insert("1.0", text)
        self.file_textbox.configure(state="disabled")
        self._set_stat_value(self.files_count_label, str(len(self.files)))

    def check_files(self):
        api_key = self.api_key_entry.get().strip()

        if not api_key or not self.files:
            messagebox.showerror("Erreur", "Veuillez entrer votre cle API et selectionner des fichiers.")
            return

        if self.remember_api_var.get():
            self._save_api_key(api_key)
        else:
            self._forget_api_key()

        self.is_scanning = True
        self.malicious_found = False
        self._set_controls_state("disabled")
        self._clear_results()
        self.progress.set(0)
        self._set_stat_value(self.threat_count_label, "0")
        self.status_label.configure(text="Analyse en cours...")

        worker = threading.Thread(target=self._scan_files, args=(api_key, list(self.files)), daemon=True)
        worker.start()

    def _scan_files(self, api_key, file_paths):
        total_files = len(file_paths)
        malicious_count = 0

        for index, file_path in enumerate(file_paths):
            self._ui(self.status_label.configure, text=f"Envoi de {Path(file_path).name} vers VirusTotal...")

            try:
                result = self._scan_single_file(api_key, file_path)
                if result["malicious"]:
                    malicious_count += 1
                    self.malicious_found = True

                self._ui(self._add_result_card, result)
                self._ui(self._set_stat_value, self.threat_count_label, str(malicious_count))
            except Exception as error:
                self._ui(self._add_error_card, file_path, str(error))

            progress_value = (index + 1) / total_files
            self._ui(self.progress.set, progress_value)

        self._ui(self._finish_scan)

    def _scan_single_file(self, api_key, file_path):
        clean_path = file_path.strip()
        response = self._send_file_to_virustotal(api_key, clean_path)

        scan_payload = self._json_or_error(response, "Echec de l'envoi du fichier")
        if response.status_code != 200 or "resource" not in scan_payload:
            detail = scan_payload.get("verbose_msg", "Erreur inconnue")
            raise RuntimeError(detail)

        report_resource = scan_payload.get("scan_id") or scan_payload["resource"]
        report = self._wait_for_report(api_key, report_resource, Path(clean_path).name)

        scans = report.get("scans", {})
        positives = int(report.get("positives", 0) or 0)
        total = int(report.get("total", len(scans)) or len(scans))
        engines = [
            {
                "engine": engine,
                "detected": bool(data.get("detected")),
                "result": data.get("result") or ("Detecte" if data.get("detected") else "Non detecte"),
                "version": data.get("version") or "Inconnu",
                "update": data.get("update") or "Inconnu",
            }
            for engine, data in scans.items()
        ]
        engines.sort(key=lambda item: (not item["detected"], item["engine"].lower()))
        detections = [
            {
                "engine": item["engine"],
                "result": item["result"],
                "version": item["version"],
            }
            for item in engines
            if item["detected"]
        ]

        return {
            "file_path": clean_path,
            "file_name": Path(clean_path).name,
            "malicious": positives > 0,
            "positives": positives,
            "total": total,
            "scan_date": report.get("scan_date") or "Inconnue",
            "scan_id": report.get("scan_id") or scan_payload.get("scan_id", "Inconnu"),
            "resource": report_resource,
            "md5": report.get("md5", "Inconnu"),
            "sha1": report.get("sha1", "Inconnu"),
            "sha256": report.get("sha256", "Inconnu"),
            "verbose_msg": report.get("verbose_msg", ""),
            "permalink": report.get("permalink", ""),
            "detections": detections,
            "engines": engines,
        }

    def _send_file_to_virustotal(self, api_key, clean_path):
        file_name = Path(clean_path).name

        for attempt in range(1, SCAN_MAX_ATTEMPTS + 1):
            with open(clean_path, "rb") as file_handle:
                response = requests.post(
                    SCAN_URL,
                    files={"file": file_handle},
                    params={"apikey": api_key},
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )

            if response.status_code != RATE_LIMIT_STATUS_CODE:
                return response

            self._wait_after_rate_limit(
                f"Limite VirusTotal atteinte pendant l'envoi de {file_name}",
                attempt,
                SCAN_MAX_ATTEMPTS,
            )

        raise RuntimeError(
            "VirusTotal limite les requetes pour le moment. "
            "Attends quelques minutes puis relance l'analyse."
        )

    def _wait_for_report(self, api_key, resource, file_name):
        last_message = "Rapport pas encore disponible"

        for attempt in range(1, REPORT_MAX_ATTEMPTS + 1):
            if attempt > 1:
                time.sleep(REPORT_POLL_INTERVAL_SECONDS)

            self._ui(
                self.status_label.configure,
                text=f"Attente du rapport VirusTotal pour {file_name} ({attempt}/{REPORT_MAX_ATTEMPTS})...",
            )

            report_response = requests.get(
                REPORT_URL,
                params={"apikey": api_key, "resource": resource},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )

            if report_response.status_code == RATE_LIMIT_STATUS_CODE:
                last_message = "Limite VirusTotal atteinte pendant la recuperation du rapport"
                self._wait_after_rate_limit(last_message, attempt, REPORT_MAX_ATTEMPTS)
                continue

            report = self._json_or_error(report_response, "Echec de recuperation du rapport")
            last_message = report.get("verbose_msg", last_message)

            if report_response.status_code != 200:
                raise RuntimeError(f"Echec de recuperation du rapport: {last_message}")

            try:
                response_code = int(report.get("response_code"))
            except (TypeError, ValueError):
                response_code = None
            if response_code == 1:
                return report

            if response_code in (-2, 0, None):
                continue

            raise RuntimeError(last_message or "Resultat introuvable pour ce fichier")

        raise RuntimeError(
            "Rapport VirusTotal pas encore disponible. "
            f"Derniere reponse: {last_message}. Reessaie dans quelques minutes."
        )

    def _wait_after_rate_limit(self, action, attempt, max_attempts):
        if attempt >= max_attempts:
            return

        self._ui(
            self.status_label.configure,
            text=f"{action}. Pause {RATE_LIMIT_WAIT_SECONDS}s ({attempt}/{max_attempts})...",
        )
        time.sleep(RATE_LIMIT_WAIT_SECONDS)

    def _json_or_error(self, response, fallback):
        try:
            return response.json()
        except ValueError as error:
            raise RuntimeError(f"{fallback}: reponse invalide ({response.status_code})") from error

    def _add_result_card(self, result):
        tone = "#ef4444" if result["malicious"] else "#22c55e"
        status_text = "Menace detectee" if result["malicious"] else "Aucun malware detecte"
        score = f"{result['positives']} / {result['total']}"

        card = ctk.CTkFrame(self.results_frame, fg_color=COLORS["card"], corner_radius=8)
        card.pack(fill="x", padx=4, pady=6)
        card.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top,
            text=result["file_name"],
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["primary_text"],
            wraplength=420,
            justify="left",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            top,
            text=score,
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=tone,
        ).grid(row=0, column=1, sticky="e", padx=(12, 0))
        ctk.CTkLabel(
            top,
            text=status_text,
            font=ctk.CTkFont(size=12),
            text_color=tone,
        ).grid(row=1, column=0, sticky="w", pady=(3, 0))

        if result["detections"]:
            detections_text = " | ".join(
                f"{item['engine']}: {item['result']}" for item in result["detections"][:8]
            )
            if len(result["detections"]) > 8:
                detections_text += f" | +{len(result['detections']) - 8} autres"
        else:
            detections_text = "Tous les moteurs consultes indiquent un resultat propre."

        ctk.CTkLabel(
            card,
            text=detections_text,
            wraplength=540,
            justify="left",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["secondary_text"],
        ).grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))

        if result["permalink"]:
            ctk.CTkLabel(
                card,
                text=result["permalink"],
                wraplength=540,
                justify="left",
                font=ctk.CTkFont(size=11),
                text_color=COLORS["link"],
            ).grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))

        ctk.CTkLabel(
            card,
            text="Rapport detaille VirusTotal",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["primary_text"],
        ).grid(row=3, column=0, sticky="w", padx=16, pady=(0, 6))

        report_box = ctk.CTkTextbox(
            card,
            height=230,
            fg_color=COLORS["input"],
            border_width=1,
            border_color=COLORS["input_border"],
            text_color=COLORS["textbox_text"],
            font=ctk.CTkFont(size=11, family="monospace"),
            wrap="none",
        )
        report_text = self._build_report_text(result)
        auto_report_path = self._auto_save_report(result, report_text)
        report_box.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 16))
        report_box.insert("1.0", report_text)
        report_box.configure(state="disabled")

        auto_report_text = (
            f"Rapport enregistre automatiquement: {auto_report_path}"
            if auto_report_path
            else "Rapport automatique non enregistre. Utilise le bouton pour choisir un dossier."
        )
        ctk.CTkLabel(
            card,
            text=auto_report_text,
            wraplength=540,
            justify="left",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["secondary_text"],
        ).grid(row=5, column=0, sticky="ew", padx=16, pady=(0, 10))

        ctk.CTkButton(
            card,
            text="Telecharger rapport",
            height=38,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            command=lambda: self._save_report(result, report_text),
        ).grid(row=6, column=0, sticky="e", padx=16, pady=(0, 16))

    def _auto_save_report(self, result, report_text):
        reports_dir = self._reports_directory()
        if reports_dir is None:
            return None

        report_path = reports_dir / self._safe_report_filename(result["file_name"], include_timestamp=True)
        try:
            report_path.write_text(report_text, encoding="utf-8")
        except OSError:
            return None

        return report_path

    def _reports_directory(self):
        reports_dir = default_documents_dir() / REPORTS_FOLDER_NAME
        try:
            reports_dir.mkdir(parents=True, exist_ok=True)
            return reports_dir
        except OSError:
            fallback_dir = Path.home() / "cKEKSAFE-Rapports"
            try:
                fallback_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                return None

            return fallback_dir

    def _save_report(self, result, report_text):
        default_name = self._safe_report_filename(result["file_name"])
        target_path = filedialog.asksaveasfilename(
            title="Enregistrer le rapport VirusTotal",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[
                ("Rapport texte", "*.txt"),
                ("Tous les fichiers", "*.*"),
            ],
        )

        if not target_path:
            return

        try:
            Path(target_path).write_text(report_text, encoding="utf-8")
        except OSError as error:
            messagebox.showerror("Telechargement rapport", f"Impossible d'enregistrer le rapport: {error}")
            return

        messagebox.showinfo("Telechargement rapport", f"Rapport enregistre:\n{target_path}")

    def _safe_report_filename(self, file_name, include_timestamp=False):
        safe_name = "".join(character if character.isalnum() or character in "._-" else "_" for character in file_name)
        safe_name = safe_name.strip("._") or "fichier"
        timestamp = f"-{datetime.now().strftime('%Y%m%d-%H%M%S')}" if include_timestamp else ""
        return f"rapport-virustotal-{safe_name}{timestamp}.txt"

    def _build_report_text(self, result):
        lines = [
            f"Fichier       : {result['file_name']}",
            f"Chemin        : {result['file_path']}",
            f"Statut        : {'MENACE DETECTEE' if result['malicious'] else 'Aucun malware detecte'}",
            f"Score         : {result['positives']} / {result['total']}",
            f"Date analyse  : {result['scan_date']}",
            f"Message VT    : {result['verbose_msg'] or 'Inconnu'}",
            f"Scan ID       : {result['scan_id']}",
            f"Resource      : {result['resource'] or 'Inconnu'}",
            f"MD5           : {result['md5']}",
            f"SHA1          : {result['sha1']}",
            f"SHA256        : {result['sha256']}",
            f"Lien VT       : {result['permalink'] or 'Non fourni'}",
            "",
            "Moteurs ayant detecte une menace:",
        ]

        if result["detections"]:
            for item in result["detections"]:
                lines.append(f"- {item['engine']}: {item['result']} (version {item['version']})")
        else:
            lines.append("- Aucun")

        lines.extend(["", "Detail moteur par moteur:"])
        for item in result["engines"]:
            status = "DETECTE" if item["detected"] else "OK"
            lines.append(
                f"- {item['engine']}: {status} | resultat={item['result']} | "
                f"version={item['version']} | update={item['update']}"
            )

        return "\n".join(lines)

    def _add_error_card(self, file_path, error):
        card = ctk.CTkFrame(self.results_frame, fg_color=COLORS["error_card"], corner_radius=8)
        card.pack(fill="x", padx=4, pady=6)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text=Path(file_path).name,
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["error_title"],
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            card,
            text=error,
            wraplength=540,
            justify="left",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["error_text"],
        ).grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))

    def _show_empty_results(self):
        empty = ctk.CTkFrame(self.results_frame, fg_color=COLORS["card"], corner_radius=8)
        empty.pack(fill="x", padx=4, pady=6)
        empty.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            empty,
            text="Les resultats apparaitront ici apres l'analyse.",
            font=ctk.CTkFont(size=14),
            text_color=COLORS["secondary_text"],
        ).grid(row=0, column=0, padx=18, pady=28)

    def _clear_results(self):
        for child in self.results_frame.winfo_children():
            child.destroy()

    def _finish_scan(self):
        self.is_scanning = False
        self._set_controls_state("normal")
        self.status_label.configure(text="Analyse terminee")

        if self.malicious_found:
            messagebox.showinfo("Termine", "Analyse terminee. Des fichiers malveillants ont ete detectes.")
        else:
            messagebox.showinfo("Termine", "Analyse terminee. Aucun fichier malveillant detecte.")

    def _set_controls_state(self, state):
        self.select_button.configure(state=state)
        self.clear_button.configure(state=state)
        self.scan_button.configure(state=state)
        self.api_key_entry.configure(state=state)
        self.remember_api_checkbox.configure(state=state)

    def _set_stat_value(self, stat_frame, value):
        stat_frame.winfo_children()[0].configure(text=value)

    def _ui(self, callback, *args, **kwargs):
        self.after(0, lambda: callback(*args, **kwargs))

    def _load_saved_api_key(self):
        try:
            if not CONFIG_PATH.exists():
                return

            with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
                config = json.load(config_file)

            api_key = config.get("api_key", "").strip()
            if api_key:
                self.api_key_entry.insert(0, api_key)
                self.remember_api_var.set(True)
        except (OSError, json.JSONDecodeError):
            return

    def _save_api_key(self, api_key):
        try:
            CONFIG_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with CONFIG_PATH.open("w", encoding="utf-8") as config_file:
                json.dump({"api_key": api_key}, config_file)

            os.chmod(CONFIG_PATH, 0o600)
        except OSError:
            messagebox.showwarning("Memoire cle API", "Impossible de memoriser la cle API.")

    def _forget_api_key(self):
        try:
            CONFIG_PATH.unlink(missing_ok=True)
        except OSError:
            messagebox.showwarning("Memoire cle API", "Impossible de supprimer la cle API memorisee.")

    def _on_remember_api_changed(self):
        api_key = self.api_key_entry.get().strip()
        if self.remember_api_var.get() and api_key:
            self._save_api_key(api_key)
        elif not self.remember_api_var.get():
            self._forget_api_key()

    def _on_close(self):
        api_key = self.api_key_entry.get().strip()
        if self.remember_api_var.get() and api_key:
            self._save_api_key(api_key)
        elif not self.remember_api_var.get():
            self._forget_api_key()

        self.destroy()

    def set_appearance(self, value):
        modes = {"Sombre": "dark", "Clair": "light", "Systeme": "system"}
        ctk.set_appearance_mode(modes.get(value, "dark"))


if __name__ == "__main__":
    app = CkekSafeApp()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        app.destroy()
