
from __future__ import annotations

import json
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import crypto
from .attacks import simulate_mitm, simulate_replay
from .models import CertInfo
from .storage import DataStore, KeyStore, load_cert_pem, load_private_key, load_public_key, save_cert_pem, save_private_key_pem, save_public_key_pem
from .utils import b64d, b64e, cert_fingerprint_sha256, read_json, safe_write_bytes, safe_write_text, write_json


APP_TITLE = "PKI Forge - Cryptographic Tool"

# Light theme palette
COLOR_BG = "#f7f9fc"
COLOR_SURFACE = "#ffffff"
COLOR_BORDER = "#e4e9f2"
COLOR_TEXT = "#0f172a"
COLOR_MUTED = "#4b5563"
COLOR_ACCENT = "#2563eb"
COLOR_ACCENT_2 = "#0ea5e9"

FONT_BASE = ("Segoe UI", 10)
FONT_HEADER = ("Segoe UI Semibold", 15)
FONT_SUBHEADER = ("Segoe UI Semibold", 11)
FONT_MONO = ("Cascadia Mono", 9)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1120x720")
        self.root.minsize(980, 640)
        self.root.configure(bg=COLOR_BG)
        self.base_dir = Path(__file__).resolve().parents[1]
        self.data_dir = self.base_dir / "data"
        self.output_dir = self.data_dir / "output"
        self.data_store = DataStore(self.data_dir)
        self.status_var = tk.StringVar(value="Ready")
        self._init_style()
        self._build_ui()

    def _init_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=COLOR_BG)
        style.configure("TLabel", background=COLOR_BG, foreground=COLOR_TEXT, font=FONT_BASE)
        style.configure("Header.TLabel", font=FONT_HEADER, foreground=COLOR_TEXT)
        style.configure("Subheader.TLabel", font=FONT_SUBHEADER, foreground=COLOR_MUTED)
        style.configure("TButton", font=FONT_BASE, padding=(12, 7), background=COLOR_SURFACE)
        style.map(
            "TButton",
            background=[("active", "#eef2f7")],
            foreground=[("active", COLOR_TEXT)],
        )
        style.configure("Primary.TButton", background=COLOR_ACCENT, foreground="#ffffff")
        style.map(
            "Primary.TButton",
            background=[("active", COLOR_ACCENT_2)],
            foreground=[("active", "#ffffff")],
        )
        style.configure("Secondary.TButton", background="#f3f4f6", foreground=COLOR_TEXT)
        style.map("Secondary.TButton", background=[("active", "#e5e7eb")])
        style.configure("TEntry", fieldbackground=COLOR_SURFACE, foreground=COLOR_TEXT, bordercolor=COLOR_BORDER)
        style.configure("TCombobox", fieldbackground=COLOR_SURFACE, foreground=COLOR_TEXT)
        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#eef2f7", foreground=COLOR_MUTED, padding=(16, 10))
        style.map("TNotebook.Tab", background=[("selected", COLOR_SURFACE)], foreground=[("selected", COLOR_TEXT)])
        style.configure("TLabelframe", background=COLOR_BG, foreground=COLOR_TEXT)
        style.configure("TLabelframe.Label", background=COLOR_BG, foreground=COLOR_TEXT, font=FONT_SUBHEADER)

    def _build_ui(self):
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=20, pady=(16, 8))
        ttk.Label(header, text=APP_TITLE, style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Label(header, text="PKI, Signatures, Encryption", style="Subheader.TLabel").pack(side=tk.LEFT, padx=12)
        accent = tk.Frame(self.root, height=2, bg=COLOR_ACCENT)
        accent.pack(fill=tk.X, padx=20)

        body = ttk.Frame(self.root)
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=12)

        self.notebook = ttk.Notebook(body)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._tab_keys = ttk.Frame(self.notebook)
        self._tab_sign = ttk.Frame(self.notebook)
        self._tab_encrypt = ttk.Frame(self.notebook)
        self._tab_keystore = ttk.Frame(self.notebook)
        self._tab_attacks = ttk.Frame(self.notebook)
        self._tab_logs = ttk.Frame(self.notebook)

        self.notebook.add(self._tab_keys, text="Keys & Certs")
        self.notebook.add(self._tab_sign, text="Sign / Verify")
        self.notebook.add(self._tab_encrypt, text="Encrypt / Decrypt")
        self.notebook.add(self._tab_keystore, text="Keystore")
        self.notebook.add(self._tab_attacks, text="Attack Sims")
        self.notebook.add(self._tab_logs, text="Logs")

        self._build_keys_tab()
        self._build_sign_tab()
        self._build_encrypt_tab()
        self._build_keystore_tab()
        self._build_attacks_tab()
        self._build_logs_tab()

        status = ttk.Frame(self.root)
        status.pack(fill=tk.X, padx=20, pady=(6, 14))
        ttk.Label(status, textvariable=self.status_var, style="Subheader.TLabel").pack(side=tk.LEFT)

    def _section(self, parent, title: str):
        frame = ttk.Labelframe(parent, text=title, padding=12)
        frame.configure(style="TLabelframe")
        return frame
    def _build_keys_tab(self):
        frame = self._tab_keys
        frame.configure(padding=16)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Key and Certificate Management", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(4, 12))

        section = self._section(frame, "Key Generation")
        section.grid(row=1, column=0, columnspan=3, sticky="we", pady=(0, 12))
        section.columnconfigure(1, weight=1)

        ttk.Label(section, text="Algorithm").grid(row=0, column=0, sticky="w")
        self.alg_var = tk.StringVar(value="RSA")
        ttk.Combobox(section, textvariable=self.alg_var, values=["RSA", "ECC"], width=12).grid(row=0, column=1, sticky="w")

        ttk.Label(section, text="RSA Key Size").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.rsa_size_var = tk.StringVar(value="2048")
        ttk.Combobox(section, textvariable=self.rsa_size_var, values=["2048", "3072", "4096"], width=12).grid(row=1, column=1, sticky="w", pady=(8, 0))

        ttk.Label(section, text="ECC Curve").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.curve_var = tk.StringVar(value="secp256r1")
        ttk.Combobox(section, textvariable=self.curve_var, values=["secp256r1", "secp384r1", "secp521r1"], width=14).grid(row=2, column=1, sticky="w", pady=(8, 0))

        ttk.Label(section, text="Subject CN").grid(row=3, column=0, sticky="w", pady=(8, 0))
        self.cn_var = tk.StringVar(value="Example User")
        ttk.Entry(section, textvariable=self.cn_var, width=32).grid(row=3, column=1, sticky="w", pady=(8, 0))

        ttk.Label(section, text="Validity (days)").grid(row=4, column=0, sticky="w", pady=(8, 0))
        self.days_var = tk.StringVar(value="365")
        ttk.Entry(section, textvariable=self.days_var, width=10).grid(row=4, column=1, sticky="w", pady=(8, 0))

        ttk.Label(section, text="Output Folder").grid(row=5, column=0, sticky="w", pady=(8, 0))
        self.output_var = tk.StringVar(value=str(self.output_dir))
        ttk.Entry(section, textvariable=self.output_var, width=60).grid(row=5, column=1, sticky="we", pady=(8, 0))
        ttk.Button(section, text="Browse", command=self._choose_output_dir, style="Secondary.TButton").grid(row=5, column=2, padx=8, pady=(8, 0))

        ttk.Button(section, text="Generate Key Pair", command=self._generate_keypair, style="Primary.TButton").grid(row=6, column=0, pady=12, sticky="w")
        ttk.Button(section, text="Create Self-Signed Cert", command=self._create_self_signed, style="Secondary.TButton").grid(row=6, column=1, pady=12, sticky="w")
        ttk.Button(section, text="Create CSR", command=self._create_csr, style="Secondary.TButton").grid(row=6, column=2, pady=12, sticky="w")

        csr_section = self._section(frame, "CSR Signing (CA)")
        csr_section.grid(row=2, column=0, columnspan=3, sticky="we", pady=(0, 12))
        ttk.Label(csr_section, text="Select CA key, CA certificate, and CSR to issue a signed cert.").grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Button(csr_section, text="Sign CSR", command=self._sign_csr, style="Primary.TButton").grid(row=1, column=0, pady=10, sticky="w")

        revoke_section = self._section(frame, "Certificate Revocation (CRL)")
        revoke_section.grid(row=3, column=0, columnspan=3, sticky="we")
        revoke_section.columnconfigure(1, weight=1)
        ttk.Label(revoke_section, text="Certificate to Revoke").grid(row=0, column=0, sticky="w")
        self.revoke_cert_var = tk.StringVar()
        ttk.Entry(revoke_section, textvariable=self.revoke_cert_var, width=60).grid(row=0, column=1, sticky="we")
        ttk.Button(revoke_section, text="Browse", command=self._choose_revoke_cert, style="Secondary.TButton").grid(row=0, column=2, padx=8)
        ttk.Label(revoke_section, text="Reason").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.revoke_reason_var = tk.StringVar(value="Key compromise")
        ttk.Entry(revoke_section, textvariable=self.revoke_reason_var, width=40).grid(row=1, column=1, sticky="w", pady=(8, 0))
        ttk.Button(revoke_section, text="Revoke", command=self._revoke_cert, style="Primary.TButton").grid(row=2, column=0, pady=10, sticky="w")

    def _build_sign_tab(self):
        frame = self._tab_sign
        frame.configure(padding=16)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Digital Signatures", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(4, 12))

        sign_section = self._section(frame, "Sign")
        sign_section.grid(row=1, column=0, columnspan=3, sticky="we", pady=(0, 12))
        sign_section.columnconfigure(1, weight=1)

        ttk.Label(sign_section, text="File to Sign").grid(row=0, column=0, sticky="w")
        self.sign_file_var = tk.StringVar()
        ttk.Entry(sign_section, textvariable=self.sign_file_var, width=60).grid(row=0, column=1, sticky="we")
        ttk.Button(sign_section, text="Browse", command=self._choose_sign_file, style="Secondary.TButton").grid(row=0, column=2, padx=8)

        ttk.Label(sign_section, text="Private Key (for signing)").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.sign_key_var = tk.StringVar()
        ttk.Entry(sign_section, textvariable=self.sign_key_var, width=60).grid(row=1, column=1, sticky="we", pady=(8, 0))
        ttk.Button(sign_section, text="Browse", command=self._choose_sign_key, style="Secondary.TButton").grid(row=1, column=2, padx=8, pady=(8, 0))

        ttk.Label(sign_section, text="Certificate (optional)").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.sign_cert_var = tk.StringVar()
        ttk.Entry(sign_section, textvariable=self.sign_cert_var, width=60).grid(row=2, column=1, sticky="we", pady=(8, 0))
        ttk.Button(sign_section, text="Browse", command=self._choose_sign_cert, style="Secondary.TButton").grid(row=2, column=2, padx=8)

        ttk.Label(sign_section, text="Signature Output (.json)").grid(row=3, column=0, sticky="w", pady=(8, 0))
        self.sig_out_var = tk.StringVar(value=str(self.output_dir / "signature.json"))
        ttk.Entry(sign_section, textvariable=self.sig_out_var, width=60).grid(row=3, column=1, sticky="we", pady=(8, 0))
        ttk.Button(sign_section, text="Browse", command=self._choose_sig_out, style="Secondary.TButton").grid(row=3, column=2, padx=8, pady=(8, 0))

        ttk.Button(sign_section, text="Sign File", command=self._sign_file, style="Primary.TButton").grid(row=4, column=0, pady=12, sticky="w")

        verify_section = self._section(frame, "Verify")
        verify_section.grid(row=2, column=0, columnspan=3, sticky="we")
        verify_section.columnconfigure(1, weight=1)

        ttk.Label(verify_section, text="Signature File (.json)").grid(row=0, column=0, sticky="w", pady=(4, 0))
        self.sig_in_var = tk.StringVar()
        ttk.Entry(verify_section, textvariable=self.sig_in_var, width=60).grid(row=0, column=1, sticky="we", pady=(4, 0))
        ttk.Button(verify_section, text="Browse", command=self._choose_sig_in, style="Secondary.TButton").grid(row=0, column=2, padx=8, pady=(4, 0))

        ttk.Label(verify_section, text="Public Key / Cert").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.verify_key_var = tk.StringVar()
        ttk.Entry(verify_section, textvariable=self.verify_key_var, width=60).grid(row=1, column=1, sticky="we", pady=(8, 0))
        ttk.Button(verify_section, text="Browse", command=self._choose_verify_key, style="Secondary.TButton").grid(row=1, column=2, padx=8)

        ttk.Button(verify_section, text="Verify", command=self._verify_file, style="Primary.TButton").grid(row=2, column=0, pady=12, sticky="w")
    def _build_encrypt_tab(self):
        frame = self._tab_encrypt
        frame.configure(padding=16)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Hybrid Encryption", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(4, 12))

        enc_section = self._section(frame, "Encrypt")
        enc_section.grid(row=1, column=0, columnspan=3, sticky="we", pady=(0, 12))
        enc_section.columnconfigure(1, weight=1)

        ttk.Label(enc_section, text="File to Encrypt").grid(row=0, column=0, sticky="w")
        self.enc_file_var = tk.StringVar()
        ttk.Entry(enc_section, textvariable=self.enc_file_var, width=60).grid(row=0, column=1, sticky="we")
        ttk.Button(enc_section, text="Browse", command=self._choose_enc_file, style="Secondary.TButton").grid(row=0, column=2, padx=8)

        ttk.Label(enc_section, text="Recipient Public Key / Cert").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.enc_pub_var = tk.StringVar()
        ttk.Entry(enc_section, textvariable=self.enc_pub_var, width=60).grid(row=1, column=1, sticky="we", pady=(8, 0))
        ttk.Button(enc_section, text="Browse", command=self._choose_enc_pub, style="Secondary.TButton").grid(row=1, column=2, padx=8, pady=(8, 0))

        ttk.Label(enc_section, text="Encrypted Output (.json)").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.enc_out_var = tk.StringVar(value=str(self.output_dir / "encrypted.json"))
        ttk.Entry(enc_section, textvariable=self.enc_out_var, width=60).grid(row=2, column=1, sticky="we", pady=(8, 0))
        ttk.Button(enc_section, text="Browse", command=self._choose_enc_out, style="Secondary.TButton").grid(row=2, column=2, padx=8)

        ttk.Button(enc_section, text="Encrypt", command=self._encrypt_file, style="Primary.TButton").grid(row=3, column=0, pady=12, sticky="w")

        dec_section = self._section(frame, "Decrypt")
        dec_section.grid(row=2, column=0, columnspan=3, sticky="we")
        dec_section.columnconfigure(1, weight=1)

        ttk.Label(dec_section, text="Encrypted Input (.json)").grid(row=0, column=0, sticky="w")
        self.dec_in_var = tk.StringVar()
        ttk.Entry(dec_section, textvariable=self.dec_in_var, width=60).grid(row=0, column=1, sticky="we")
        ttk.Button(dec_section, text="Browse", command=self._choose_dec_in, style="Secondary.TButton").grid(row=0, column=2, padx=8)

        ttk.Label(dec_section, text="Recipient Private Key").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.dec_key_var = tk.StringVar()
        ttk.Entry(dec_section, textvariable=self.dec_key_var, width=60).grid(row=1, column=1, sticky="we", pady=(8, 0))
        ttk.Button(dec_section, text="Browse", command=self._choose_dec_key, style="Secondary.TButton").grid(row=1, column=2, padx=8, pady=(8, 0))

        ttk.Label(dec_section, text="Decrypted Output File").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.dec_out_var = tk.StringVar(value=str(self.output_dir / "decrypted.out"))
        ttk.Entry(dec_section, textvariable=self.dec_out_var, width=60).grid(row=2, column=1, sticky="we", pady=(8, 0))
        ttk.Button(dec_section, text="Browse", command=self._choose_dec_out, style="Secondary.TButton").grid(row=2, column=2, padx=8)

        ttk.Button(dec_section, text="Decrypt", command=self._decrypt_file, style="Primary.TButton").grid(row=3, column=0, pady=12, sticky="w")

    def _build_keystore_tab(self):
        frame = self._tab_keystore
        frame.configure(padding=16)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Password-Protected Keystore (PKCS#12)", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(4, 12))

        create_section = self._section(frame, "Create Keystore")
        create_section.grid(row=1, column=0, columnspan=3, sticky="we", pady=(0, 12))
        create_section.columnconfigure(1, weight=1)

        ttk.Label(create_section, text="Private Key").grid(row=0, column=0, sticky="w")
        self.ks_key_var = tk.StringVar()
        ttk.Entry(create_section, textvariable=self.ks_key_var, width=60).grid(row=0, column=1, sticky="we")
        ttk.Button(create_section, text="Browse", command=self._choose_ks_key, style="Secondary.TButton").grid(row=0, column=2, padx=8)

        ttk.Label(create_section, text="Certificate").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.ks_cert_var = tk.StringVar()
        ttk.Entry(create_section, textvariable=self.ks_cert_var, width=60).grid(row=1, column=1, sticky="we", pady=(8, 0))
        ttk.Button(create_section, text="Browse", command=self._choose_ks_cert, style="Secondary.TButton").grid(row=1, column=2, padx=8, pady=(8, 0))

        ttk.Label(create_section, text="Keystore Password").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.ks_pwd_var = tk.StringVar()
        ttk.Entry(create_section, textvariable=self.ks_pwd_var, width=20, show="*").grid(row=2, column=1, sticky="w", pady=(8, 0))

        ttk.Label(create_section, text="Keystore Output (.p12)").grid(row=3, column=0, sticky="w", pady=(8, 0))
        self.ks_out_var = tk.StringVar(value=str(self.output_dir / "keystore.p12"))
        ttk.Entry(create_section, textvariable=self.ks_out_var, width=60).grid(row=3, column=1, sticky="we", pady=(8, 0))
        ttk.Button(create_section, text="Browse", command=self._choose_ks_out, style="Secondary.TButton").grid(row=3, column=2, padx=8, pady=(8, 0))

        ttk.Button(create_section, text="Create Keystore", command=self._create_keystore, style="Primary.TButton").grid(row=4, column=0, pady=12, sticky="w")

        load_section = self._section(frame, "Load Keystore")
        load_section.grid(row=2, column=0, columnspan=3, sticky="we")
        load_section.columnconfigure(1, weight=1)
        ttk.Label(load_section, text="Keystore File (.p12)").grid(row=0, column=0, sticky="w")
        self.ks_in_var = tk.StringVar()
        ttk.Entry(load_section, textvariable=self.ks_in_var, width=60).grid(row=0, column=1, sticky="we")
        ttk.Button(load_section, text="Browse", command=self._choose_ks_in, style="Secondary.TButton").grid(row=0, column=2, padx=8)

        ttk.Label(load_section, text="Password").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.ks_in_pwd_var = tk.StringVar()
        ttk.Entry(load_section, textvariable=self.ks_in_pwd_var, width=20, show="*").grid(row=1, column=1, sticky="w", pady=(8, 0))

        ttk.Button(load_section, text="Load Keystore", command=self._load_keystore, style="Primary.TButton").grid(row=2, column=0, pady=12, sticky="w")
    def _build_attacks_tab(self):
        frame = self._tab_attacks
        frame.configure(padding=16)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Attack Simulations", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(4, 12))

        mitm_section = self._section(frame, "MITM Detection (Certificate Pinning)")
        mitm_section.grid(row=1, column=0, columnspan=3, sticky="we", pady=(0, 12))
        mitm_section.columnconfigure(1, weight=1)
        ttk.Label(mitm_section, text="Expected Cert").grid(row=0, column=0, sticky="w")
        self.mitm_expected_var = tk.StringVar()
        ttk.Entry(mitm_section, textvariable=self.mitm_expected_var, width=60).grid(row=0, column=1, sticky="we")
        ttk.Button(mitm_section, text="Browse", command=self._choose_mitm_expected, style="Secondary.TButton").grid(row=0, column=2, padx=8)

        ttk.Label(mitm_section, text="Presented Cert").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.mitm_presented_var = tk.StringVar()
        ttk.Entry(mitm_section, textvariable=self.mitm_presented_var, width=60).grid(row=1, column=1, sticky="we", pady=(8, 0))
        ttk.Button(mitm_section, text="Browse", command=self._choose_mitm_presented, style="Secondary.TButton").grid(row=1, column=2, padx=8, pady=(8, 0))

        ttk.Button(mitm_section, text="Simulate MITM", command=self._simulate_mitm, style="Primary.TButton").grid(row=2, column=0, pady=12, sticky="w")

        replay_section = self._section(frame, "Replay Attack Simulation")
        replay_section.grid(row=2, column=0, columnspan=3, sticky="we")
        replay_section.columnconfigure(1, weight=1)
        ttk.Label(replay_section, text="Nonce Value").grid(row=0, column=0, sticky="w")
        self.replay_nonce_var = tk.StringVar()
        ttk.Entry(replay_section, textvariable=self.replay_nonce_var, width=40).grid(row=0, column=1, sticky="w")
        ttk.Button(replay_section, text="Simulate Replay", command=self._simulate_replay, style="Primary.TButton").grid(row=0, column=2, padx=8)

    def _build_logs_tab(self):
        frame = self._tab_logs
        frame.configure(padding=16)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text="Activity Log", style="Header.TLabel").grid(row=0, column=0, sticky="w", pady=(4, 12))
        self.log_text = tk.Text(
            frame,
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            height=24,
            relief=tk.FLAT,
            font=FONT_MONO,
        )
        scroll = ttk.Scrollbar(frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.grid(row=1, column=0, sticky="nsew")
        scroll.grid(row=1, column=1, sticky="ns")
        frame.rowconfigure(1, weight=1)

    def _log(self, msg: str):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.status_var.set(msg)
    def _choose_output_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.output_var.set(path)

    def _choose_sign_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.sign_file_var.set(path)

    def _choose_sign_key(self):
        path = filedialog.askopenfilename()
        if path:
            self.sign_key_var.set(path)

    def _choose_sign_cert(self):
        path = filedialog.askopenfilename()
        if path:
            self.sign_cert_var.set(path)

    def _choose_sig_out(self):
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if path:
            self.sig_out_var.set(path)

    def _choose_sig_in(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if path:
            self.sig_in_var.set(path)

    def _choose_verify_key(self):
        path = filedialog.askopenfilename()
        if path:
            self.verify_key_var.set(path)

    def _choose_enc_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.enc_file_var.set(path)

    def _choose_enc_pub(self):
        path = filedialog.askopenfilename()
        if path:
            self.enc_pub_var.set(path)

    def _choose_enc_out(self):
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if path:
            self.enc_out_var.set(path)

    def _choose_dec_in(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if path:
            self.dec_in_var.set(path)

    def _choose_dec_key(self):
        path = filedialog.askopenfilename()
        if path:
            self.dec_key_var.set(path)

    def _choose_dec_out(self):
        path = filedialog.asksaveasfilename()
        if path:
            self.dec_out_var.set(path)

    def _choose_ks_key(self):
        path = filedialog.askopenfilename()
        if path:
            self.ks_key_var.set(path)

    def _choose_ks_cert(self):
        path = filedialog.askopenfilename()
        if path:
            self.ks_cert_var.set(path)

    def _choose_ks_out(self):
        path = filedialog.asksaveasfilename(defaultextension=".p12")
        if path:
            self.ks_out_var.set(path)

    def _choose_ks_in(self):
        path = filedialog.askopenfilename(filetypes=[("PKCS12", "*.p12")])
        if path:
            self.ks_in_var.set(path)

    def _choose_mitm_expected(self):
        path = filedialog.askopenfilename()
        if path:
            self.mitm_expected_var.set(path)

    def _choose_mitm_presented(self):
        path = filedialog.askopenfilename()
        if path:
            self.mitm_presented_var.set(path)

    def _choose_revoke_cert(self):
        path = filedialog.askopenfilename()
        if path:
            self.revoke_cert_var.set(path)
    def _generate_keypair(self):
        alg = self.alg_var.get()
        key_size = int(self.rsa_size_var.get())
        curve = self.curve_var.get()
        priv, pub = crypto.generate_keypair(alg, key_size, curve)
        out_dir = Path(self.output_var.get())
        save_private_key_pem(out_dir / "private_key.pem", priv, None)
        save_public_key_pem(out_dir / "public_key.pem", pub)
        self._log(f"Generated {alg} key pair at {out_dir}")

    def _create_self_signed(self):
        alg = self.alg_var.get()
        key_size = int(self.rsa_size_var.get())
        curve = self.curve_var.get()
        subject_cn = self.cn_var.get()
        days = int(self.days_var.get())
        priv, _ = crypto.generate_keypair(alg, key_size, curve)
        cert = crypto.create_self_signed_cert(priv, subject_cn, days)
        out_dir = Path(self.output_var.get())
        save_private_key_pem(out_dir / "private_key.pem", priv, None)
        save_cert_pem(out_dir / "certificate.pem", cert)
        self._log(f"Created self-signed cert for {subject_cn}")

    def _create_csr(self):
        alg = self.alg_var.get()
        key_size = int(self.rsa_size_var.get())
        curve = self.curve_var.get()
        subject_cn = self.cn_var.get()
        priv, _ = crypto.generate_keypair(alg, key_size, curve)
        csr = crypto.create_csr(priv, subject_cn)
        out_dir = Path(self.output_var.get())
        save_private_key_pem(out_dir / "csr_private_key.pem", priv, None)
        safe_write_bytes(out_dir / "request.csr", csr.public_bytes(serialization.Encoding.PEM))
        self._log(f"CSR created for {subject_cn}")

    def _sign_csr(self):
        ca_key_path = filedialog.askopenfilename(title="Select CA Private Key")
        ca_cert_path = filedialog.askopenfilename(title="Select CA Certificate")
        csr_path = filedialog.askopenfilename(title="Select CSR")
        if not (ca_key_path and ca_cert_path and csr_path):
            return
        ca_key = load_private_key(Path(ca_key_path), None)
        ca_cert = load_cert_pem(Path(ca_cert_path))
        csr = x509.load_pem_x509_csr(Path(csr_path).read_bytes())
        days = int(self.days_var.get())
        cert = crypto.sign_csr(ca_key, ca_cert, csr, days)
        out_dir = Path(self.output_var.get())
        save_cert_pem(out_dir / "signed_certificate.pem", cert)
        self._log("CSR signed by CA")

    def _sign_file(self):
        if not self.sign_file_var.get() or not self.sign_key_var.get():
            messagebox.showwarning("Missing", "Please select file and private key")
            return
        file_path = Path(self.sign_file_var.get())
        key_path = Path(self.sign_key_var.get())
        cert_path = self.sign_cert_var.get()
        signer_cert = load_cert_pem(Path(cert_path)) if cert_path else None
        private_key = load_private_key(key_path, None)
        blob = crypto.sign_file(file_path, private_key, signer_cert, self.data_store)
        out_path = Path(self.sig_out_var.get())
        write_json(out_path, blob)
        self._log(f"Signed file {file_path.name} -> {out_path}")

    def _verify_file(self):
        if not self.sign_file_var.get() or not self.sig_in_var.get() or not self.verify_key_var.get():
            messagebox.showwarning("Missing", "Select file, signature, and public key/cert")
            return
        file_path = Path(self.sign_file_var.get())
        sig_path = Path(self.sig_in_var.get())
        sig_blob = read_json(sig_path)
        key_path = Path(self.verify_key_var.get())
        if key_path.suffix.lower() in {".pem", ".crt", ".cer"}:
            try:
                cert = load_cert_pem(key_path)
                public_key = cert.public_key()
                if self.data_store.is_revoked(cert_fingerprint_sha256(cert)):
                    self._log("Verification failed: certificate revoked")
                    messagebox.showerror("Revoked", "Certificate revoked")
                    return
            except Exception:
                public_key = load_public_key(key_path)
        else:
            public_key = load_public_key(key_path)
        result = crypto.verify_file(file_path, sig_blob, public_key, self.data_store)
        self._log(f"Verify: {result.reason}")
        if result.ok:
            messagebox.showinfo("Verified", result.reason)
        else:
            messagebox.showerror("Invalid", result.reason)

    def _encrypt_file(self):
        if not self.enc_file_var.get() or not self.enc_pub_var.get():
            messagebox.showwarning("Missing", "Select file and recipient public key/cert")
            return
        file_path = Path(self.enc_file_var.get())
        pub_path = Path(self.enc_pub_var.get())
        try:
            cert = load_cert_pem(pub_path)
            public_key = cert.public_key()
        except Exception:
            public_key = load_public_key(pub_path)
        blob = crypto.encrypt_file(file_path, public_key)
        out_path = Path(self.enc_out_var.get())
        write_json(out_path, blob)
        self._log(f"Encrypted {file_path.name} -> {out_path}")

    def _decrypt_file(self):
        if not self.dec_in_var.get() or not self.dec_key_var.get():
            messagebox.showwarning("Missing", "Select encrypted file and private key")
            return
        blob = read_json(Path(self.dec_in_var.get()))
        key_path = Path(self.dec_key_var.get())
        private_key = load_private_key(key_path, None)
        out_path = Path(self.dec_out_var.get())
        result = crypto.decrypt_file(blob, private_key, out_path)
        self._log(result.reason)
        if result.ok:
            messagebox.showinfo("Decrypted", result.reason)
        else:
            messagebox.showerror("Decrypt failed", result.reason)

    def _create_keystore(self):
        if not (self.ks_key_var.get() and self.ks_cert_var.get() and self.ks_pwd_var.get()):
            messagebox.showwarning("Missing", "Provide key, cert, and password")
            return
        key = load_private_key(Path(self.ks_key_var.get()), None)
        cert = load_cert_pem(Path(self.ks_cert_var.get()))
        ks = KeyStore(Path(self.ks_out_var.get()))
        ks.save_pkcs12(key, cert, self.ks_pwd_var.get(), "pki-gui")
        self._log(f"Keystore created at {self.ks_out_var.get()}")

    def _load_keystore(self):
        if not (self.ks_in_var.get() and self.ks_in_pwd_var.get()):
            messagebox.showwarning("Missing", "Provide keystore and password")
            return
        ks = KeyStore(Path(self.ks_in_var.get()))
        key, cert = ks.load_pkcs12(self.ks_in_pwd_var.get())
        self._log(f"Loaded keystore. Cert fingerprint: {cert_fingerprint_sha256(cert)}")

    def _simulate_mitm(self):
        if not (self.mitm_expected_var.get() and self.mitm_presented_var.get()):
            messagebox.showwarning("Missing", "Provide both certs")
            return
        expected = load_cert_pem(Path(self.mitm_expected_var.get()))
        presented = load_cert_pem(Path(self.mitm_presented_var.get()))
        result = simulate_mitm(expected, presented)
        self._log(result["result"])
        if result["ok"] == "true":
            messagebox.showinfo("MITM", result["result"])
        else:
            messagebox.showwarning("MITM", result["result"])

    def _simulate_replay(self):
        nonce = self.replay_nonce_var.get().strip()
        if not nonce:
            messagebox.showwarning("Missing", "Provide a nonce")
            return
        result = simulate_replay(self.data_store, nonce)
        self._log(result["result"])
        if result["ok"] == "true":
            messagebox.showinfo("Replay", result["result"])
        else:
            messagebox.showwarning("Replay", result["result"])

    def _revoke_cert(self):
        if not self.revoke_cert_var.get():
            messagebox.showwarning("Missing", "Select a certificate to revoke")
            return
        cert = load_cert_pem(Path(self.revoke_cert_var.get()))
        fp = cert_fingerprint_sha256(cert)
        reason = self.revoke_reason_var.get().strip() or "Unspecified"
        self.data_store.add_revoked(fp, reason)
        self._log(f"Revoked cert fingerprint {fp} ({reason})")
        messagebox.showinfo("Revoked", "Certificate revoked and added to CRL")


def run_app():
    root = tk.Tk()
    app = App(root)
    root.mainloop()
