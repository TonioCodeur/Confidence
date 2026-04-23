"""
main.py — Point d'entrée de l'application Confidence.
"""

import sys
from PyQt6.QtWidgets import QApplication
from ui import MainWindow, DARK_STYLESHEET


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
