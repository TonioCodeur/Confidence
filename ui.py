"""
Confidence - Interface graphique de chiffrement/dechiffrement de fichiers.

Module UI (PyQt6) - Concu par DF.
Appelle les fonctions encrypt_file() et decrypt_file() fournies par le module crypto.py (DB).
Supporte le traitement de plusieurs fichiers en une seule operation.
"""

import sys
import os
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QProgressBar,
    QFileDialog,
    QMessageBox,
    QCheckBox,
    QFrame,
    QListWidget,
    QListWidgetItem,
    QAbstractItemView,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont


# ---------------------------------------------------------------------------
# Worker thread : execute le chiffrement/dechiffrement sans bloquer l'UI
# ---------------------------------------------------------------------------
class CryptoWorker(QThread):
    """Thread de travail pour les operations de chiffrement/dechiffrement en lot."""

    # (index_courant, total) — emis avant chaque fichier
    progress = pyqtSignal(int, int)
    # (chemin_source, chemin_sortie) — succes d'un fichier
    file_done = pyqtSignal(str, str)
    # (chemin_source, message_erreur) — echec d'un fichier
    file_error = pyqtSignal(str, str)
    # (nb_succes, nb_erreurs) — emis quand tous les fichiers sont traites
    all_done = pyqtSignal(int, int)

    def __init__(self, operation: str, filepaths: list[str], key: str):
        super().__init__()
        self.operation = operation   # "encrypt" ou "decrypt"
        self.filepaths = filepaths
        self.key = key

    def run(self):
        try:
            from crypto import encrypt_file, decrypt_file
        except ImportError:
            # Signaler l'erreur pour chaque fichier et stopper
            for fp in self.filepaths:
                self.file_error.emit(
                    fp,
                    "Le module crypto.py est introuvable. "
                    "Assurez-vous qu'il se trouve dans le meme repertoire que ui.py.",
                )
            self.all_done.emit(0, len(self.filepaths))
            return

        total = len(self.filepaths)
        successes = 0
        errors = 0

        for idx, filepath in enumerate(self.filepaths):
            self.progress.emit(idx + 1, total)
            try:
                if self.operation == "encrypt":
                    output_path = encrypt_file(filepath, self.key)
                else:
                    output_path = decrypt_file(filepath, self.key)
                self.file_done.emit(filepath, output_path)
                successes += 1
            except Exception as exc:
                self.file_error.emit(filepath, str(exc))
                errors += 1

        self.all_done.emit(successes, errors)


# ---------------------------------------------------------------------------
# Feuille de style globale (theme sombre moderne, palette Catppuccin Mocha)
# ---------------------------------------------------------------------------
DARK_STYLESHEET = """
QMainWindow {
    background-color: #1e1e2e;
}

QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: "Segoe UI", "Inter", "Roboto", sans-serif;
    font-size: 14px;
}

QLabel {
    color: #cdd6f4;
    font-size: 14px;
}

QLabel#titleLabel {
    font-size: 26px;
    font-weight: bold;
    color: #89b4fa;
    padding: 8px 0;
}

QLabel#subtitleLabel {
    font-size: 13px;
    color: #6c7086;
    padding-bottom: 4px;
}

QLineEdit {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 8px 12px;
    color: #cdd6f4;
    font-size: 14px;
    selection-background-color: #89b4fa;
}

QLineEdit:focus {
    border: 1px solid #89b4fa;
}

QListWidget {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 6px;
    padding: 4px;
    color: #cdd6f4;
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    outline: none;
}

QListWidget::item {
    padding: 4px 8px;
    border-radius: 4px;
}

QListWidget::item:selected {
    background-color: #313244;
    color: #89b4fa;
}

QListWidget::item:hover:!selected {
    background-color: #24273a;
}

QPushButton {
    border-radius: 6px;
    padding: 8px 18px;
    font-size: 14px;
    font-weight: 600;
    border: none;
}

QPushButton#browseBtn {
    background-color: #45475a;
    color: #cdd6f4;
}
QPushButton#browseBtn:hover {
    background-color: #585b70;
}

QPushButton#clearBtn {
    background-color: #313244;
    color: #f38ba8;
    padding: 8px 14px;
}
QPushButton#clearBtn:hover {
    background-color: #45475a;
}

QPushButton#removeBtn {
    background-color: #313244;
    color: #fab387;
    padding: 8px 14px;
    font-size: 13px;
}
QPushButton#removeBtn:hover {
    background-color: #45475a;
}

QPushButton#encryptBtn {
    background-color: #a6e3a1;
    color: #1e1e2e;
    font-size: 15px;
    padding: 10px 28px;
}
QPushButton#encryptBtn:hover {
    background-color: #94e2d5;
}
QPushButton#encryptBtn:disabled {
    background-color: #45475a;
    color: #6c7086;
}

QPushButton#decryptBtn {
    background-color: #89b4fa;
    color: #1e1e2e;
    font-size: 15px;
    padding: 10px 28px;
}
QPushButton#decryptBtn:hover {
    background-color: #74c7ec;
}
QPushButton#decryptBtn:disabled {
    background-color: #45475a;
    color: #6c7086;
}

QCheckBox {
    color: #a6adc8;
    spacing: 6px;
    font-size: 13px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 3px;
    border: 1px solid #585b70;
    background-color: #313244;
}
QCheckBox::indicator:checked {
    background-color: #89b4fa;
    border: 1px solid #89b4fa;
}

QTextEdit {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 6px;
    padding: 8px;
    color: #a6adc8;
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 13px;
}

QProgressBar {
    background-color: #313244;
    border: none;
    border-radius: 4px;
    height: 6px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk {
    background-color: #89b4fa;
    border-radius: 4px;
}

QFrame#separator {
    background-color: #313244;
    max-height: 1px;
}
"""


# ---------------------------------------------------------------------------
# Fenetre principale
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    """Fenetre principale de l'application Confidence."""

    def __init__(self):
        super().__init__()
        self._worker = None  # reference au thread en cours
        self._init_ui()

    # ---- Construction de l'interface ----

    def _init_ui(self):
        """Initialise tous les widgets et layouts."""
        self.setWindowTitle("Confidence")
        self.setMinimumSize(660, 620)
        self.resize(720, 680)

        # Widget central
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(32, 24, 32, 24)
        root_layout.setSpacing(14)

        # --- Titre ---
        title = QLabel("Confidence")
        title.setObjectName("titleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root_layout.addWidget(title)

        subtitle = QLabel("Chiffrement et dechiffrement de fichiers — simple et securise")
        subtitle.setObjectName("subtitleLabel")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root_layout.addWidget(subtitle)

        # Separateur
        sep1 = QFrame()
        sep1.setObjectName("separator")
        sep1.setFrameShape(QFrame.Shape.HLine)
        root_layout.addWidget(sep1)

        # --- Fichiers ---
        file_header = QHBoxLayout()
        file_label = QLabel("Fichiers")
        file_label.setStyleSheet("font-weight: 600;")
        file_header.addWidget(file_label)
        file_header.addStretch()

        # Compteur de fichiers
        self.file_count_label = QLabel("0 fichier(s)")
        self.file_count_label.setStyleSheet("color: #6c7086; font-size: 12px;")
        file_header.addWidget(self.file_count_label)
        root_layout.addLayout(file_header)

        # Liste des fichiers selectionnes
        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.file_list.setMinimumHeight(120)
        self.file_list.setMaximumHeight(160)
        self.file_list.setToolTip(
            "Selectionnez des elements puis cliquez sur 'Retirer' pour les supprimer."
        )
        root_layout.addWidget(self.file_list)

        # Boutons de gestion de la liste
        list_btn_row = QHBoxLayout()
        list_btn_row.setSpacing(8)

        browse_btn = QPushButton("+ Ajouter des fichiers")
        browse_btn.setObjectName("browseBtn")
        browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        browse_btn.clicked.connect(self._browse_files)
        list_btn_row.addWidget(browse_btn)

        remove_btn = QPushButton("Retirer la selection")
        remove_btn.setObjectName("removeBtn")
        remove_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        remove_btn.clicked.connect(self._remove_selected)
        list_btn_row.addWidget(remove_btn)

        clear_btn = QPushButton("Tout vider")
        clear_btn.setObjectName("clearBtn")
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.clicked.connect(self._clear_files)
        list_btn_row.addWidget(clear_btn)

        list_btn_row.addStretch()
        root_layout.addLayout(list_btn_row)

        # --- Cle de chiffrement ---
        key_label = QLabel("Cle de chiffrement")
        key_label.setStyleSheet("font-weight: 600;")
        root_layout.addWidget(key_label)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Entrez votre cle secrete...")
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        root_layout.addWidget(self.key_input)

        self.show_key_cb = QCheckBox("Afficher la cle")
        self.show_key_cb.toggled.connect(self._toggle_key_visibility)
        root_layout.addWidget(self.show_key_cb)

        # --- Boutons d'action ---
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.encrypt_btn = QPushButton("Chiffrer")
        self.encrypt_btn.setObjectName("encryptBtn")
        self.encrypt_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.encrypt_btn.clicked.connect(self._on_encrypt)
        btn_row.addWidget(self.encrypt_btn)

        self.decrypt_btn = QPushButton("Dechiffrer")
        self.decrypt_btn.setObjectName("decryptBtn")
        self.decrypt_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.decrypt_btn.clicked.connect(self._on_decrypt)
        btn_row.addWidget(self.decrypt_btn)

        root_layout.addLayout(btn_row)

        # --- Barre de progression (determinee) ---
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        root_layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color: #6c7086; font-size: 12px;")
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_label.setVisible(False)
        root_layout.addWidget(self.progress_label)

        # Separateur
        sep2 = QFrame()
        sep2.setObjectName("separator")
        sep2.setFrameShape(QFrame.Shape.HLine)
        root_layout.addWidget(sep2)

        # --- Zone de log ---
        log_label = QLabel("Journal")
        log_label.setStyleSheet("font-weight: 600;")
        root_layout.addWidget(log_label)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setPlaceholderText("Les messages apparaitront ici...")
        root_layout.addWidget(self.log_area, stretch=1)

    # ---- Gestion de la liste de fichiers ----

    def _browse_files(self):
        """Ouvre un dialogue de selection multi-fichiers et les ajoute a la liste."""
        filepaths, _ = QFileDialog.getOpenFileNames(
            self,
            "Selectionner des fichiers",
            "",
            "Tous les fichiers (*)",
        )
        added = 0
        for fp in filepaths:
            if not self._is_already_in_list(fp):
                self.file_list.addItem(fp)
                added += 1
        if added:
            self._update_file_count()

    def _is_already_in_list(self, filepath: str) -> bool:
        """Retourne True si le fichier est deja dans la liste (evite les doublons)."""
        for i in range(self.file_list.count()):
            if self.file_list.item(i).text() == filepath:
                return True
        return False

    def _remove_selected(self):
        """Retire les elements selectionnes de la liste."""
        for item in self.file_list.selectedItems():
            self.file_list.takeItem(self.file_list.row(item))
        self._update_file_count()

    def _clear_files(self):
        """Vide la liste de fichiers."""
        self.file_list.clear()
        self._update_file_count()

    def _update_file_count(self):
        """Met a jour le label de comptage."""
        n = self.file_list.count()
        self.file_count_label.setText(f"{n} fichier(s)")

    def _get_filepaths(self) -> list[str]:
        """Retourne la liste des chemins actuellement dans le widget."""
        return [self.file_list.item(i).text() for i in range(self.file_list.count())]

    # ---- Slots ----

    def _toggle_key_visibility(self, checked: bool):
        """Affiche ou masque la cle de chiffrement."""
        if checked:
            self.key_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.key_input.setEchoMode(QLineEdit.EchoMode.Password)

    def _validate_inputs(self) -> bool:
        """Verifie que la liste n'est pas vide, que les fichiers existent
        et que la cle est renseignee."""
        filepaths = self._get_filepaths()

        if not filepaths:
            QMessageBox.warning(
                self,
                "Aucun fichier",
                "Veuillez ajouter au moins un fichier a traiter.",
            )
            return False

        missing = [fp for fp in filepaths if not os.path.isfile(fp)]
        if missing:
            QMessageBox.warning(
                self,
                "Fichier(s) introuvable(s)",
                "Les fichiers suivants n'existent pas :\n" + "\n".join(missing),
            )
            return False

        if not self.key_input.text():
            QMessageBox.warning(
                self, "Cle manquante", "Veuillez saisir une cle de chiffrement."
            )
            return False

        return True

    def _start_operation(self, operation: str):
        """Lance le worker pour chiffrer ou dechiffrer tous les fichiers de la liste."""
        if not self._validate_inputs():
            return

        filepaths = self._get_filepaths()
        key = self.key_input.text()
        total = len(filepaths)

        # Desactiver les boutons et afficher la progression
        self.encrypt_btn.setEnabled(False)
        self.decrypt_btn.setEnabled(False)
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.progress_label.setText(f"0 / {total}")
        self.progress_label.setVisible(True)

        label = "Chiffrement" if operation == "encrypt" else "Dechiffrement"
        self._log(f"--- {label} de {total} fichier(s) ---")

        self._worker = CryptoWorker(operation, filepaths, key)
        self._worker.progress.connect(self._on_progress)
        self._worker.file_done.connect(self._on_file_done)
        self._worker.file_error.connect(self._on_file_error)
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    def _on_encrypt(self):
        """Slot du bouton Chiffrer."""
        self._start_operation("encrypt")

    def _on_decrypt(self):
        """Slot du bouton Dechiffrer."""
        self._start_operation("decrypt")

    def _on_progress(self, current: int, total: int):
        """Mise a jour de la barre de progression."""
        self.progress_bar.setValue(current)
        self.progress_label.setText(f"{current} / {total}")

    def _on_file_done(self, source: str, output: str):
        """Callback quand un fichier est traite avec succes."""
        name = Path(source).name
        self._log(f"  ✓  {name}  →  {output}")

    def _on_file_error(self, source: str, error_msg: str):
        """Callback quand un fichier echoue."""
        name = Path(source).name
        self._log(f"  ✗  {name}  →  ERREUR : {error_msg}")

    def _on_all_done(self, successes: int, errors: int):
        """Callback quand tous les fichiers ont ete traites."""
        total = successes + errors
        if errors == 0:
            self._log(f"--- Termine : {successes}/{total} fichier(s) traite(s) avec succes ---")
        else:
            self._log(
                f"--- Termine : {successes} succes, {errors} erreur(s) sur {total} fichier(s) ---"
            )
            QMessageBox.warning(
                self,
                "Traitement partiel",
                f"{errors} fichier(s) n'ont pas pu etre traite(s).\n"
                "Consultez le journal pour les details.",
            )
        self._reset_ui()

    def _reset_ui(self):
        """Reactive les boutons et masque la barre de progression."""
        self.encrypt_btn.setEnabled(True)
        self.decrypt_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self._worker = None

    def _log(self, message: str):
        """Ajoute un message horodate dans la zone de log."""
        from datetime import datetime

        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.append(f"[{timestamp}]  {message}")


# ---------------------------------------------------------------------------
# Point d'entree
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
