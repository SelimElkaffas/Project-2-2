import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont
from gui.main import MainWindow
def main():
    app = QApplication(sys.argv)

    font = QFont("Inter", 10)
    app.setFont(font)

    window = MainWindow()
    if window.get_username():  # This calls the GUI dialog and performs connection
        window.show()
        sys.exit(app.exec())
    else:
        print("Username not provided or connection failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
