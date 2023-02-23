from PyQt5 import QtWidgets, QtGui, QtCore
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import datetime


class CryptoApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        # Set up the main window
        self.setWindowTitle("Cryptographic tool")
        self.setGeometry(100, 100, 500, 300)
        

        # Create a label and text field for the filename
        self.filename_label = QtWidgets.QLabel("File or folder path:", self)
        self.filename_label.move(50, 50)
        self.filename_field = QtWidgets.QLineEdit(self)
        self.filename_field.move(150, 50)
        self.filename_field.resize(200, 20)
                
        
        # Create a button to browse for the file or folder
        self.browse_button = QtWidgets.QPushButton("Browse", self)
        self.browse_button.move(360, 50)
        self.browse_button.clicked.connect(self.browse_file)

        # Create a label and text field for the password
        self.password_label = QtWidgets.QLabel("Password:", self)
        self.password_label.move(50, 100)
        self.password_field = QtWidgets.QLineEdit(self)
        self.password_field.move(150, 100)
        self.password_field.resize(200, 20)
        self.password_field.setEchoMode(QtWidgets.QLineEdit.Password)
        
         # Create a label and text field for the save directory
        self.savedir_label = QtWidgets.QLabel("Save directory:", self)
        self.savedir_label.move(50, 150)
        self.savedir_field = QtWidgets.QLineEdit(self)
        self.savedir_field.move(150, 150)
        self.savedir_field.resize(200, 20)

        # Create a button to browse for the save directory
        self.browse_savedir_button = QtWidgets.QPushButton("Browse", self)
        self.browse_savedir_button.move(360, 150)
        self.browse_savedir_button.clicked.connect(self.browse_savedir)

        # Create a label and radio buttons for the operation
        self.operation_label = QtWidgets.QLabel("Operation:", self)
        self.operation_label.move(90, 180)
        self.encrypt_radio = QtWidgets.QRadioButton("Encrypt", self)
        self.encrypt_radio.move(180, 180)
        self.decrypt_radio = QtWidgets.QRadioButton("Decrypt", self)
        self.decrypt_radio.move(270, 180)

        # Create a button for executing the operation
        self.execute_button = QtWidgets.QPushButton("Execute", self)
        self.execute_button.move(200, 230)
        self.execute_button.clicked.connect(self.execute_operation)

        # Show the main window
        self.show()
        
        
    def browse_file(self):
        # Open a file dialog to browse for the file or folder to encrypt/decrypt
        browse_type, ok = QtWidgets.QInputDialog.getItem(self, "Select browse type", "Select browse type:", ["File", "Folder"], 0, False)
        if ok:
            options = QtWidgets.QFileDialog.Options()
            options |= QtWidgets.QFileDialog.DontUseNativeDialog
            if browse_type == "File":
                file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file", "", "All Files (*)", options=options)
                if file_path:
                    self.filename_field.setText(file_path)
            elif browse_type == "Folder":
                dir_path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder", "", options=options)
                if dir_path:
                    self.filename_field.setText(dir_path)


    def browse_savedir(self):
    #Open a directory dialog to browse for the save directory
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        dir_path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select save directory", "", options=options)
        if dir_path:
            self.savedir_field.setText(dir_path)


    def execute_operation(self):
        filename = self.filename_field.text()
        password = self.password_field.text()
        savedir = self.savedir_field.text()

        if not os.path.exists(filename):
            error_dialog = QtWidgets.QErrorMessage()
            error_dialog.showMessage("File or folder does not exist.")
            error_dialog.exec_()
            return

        if not password:
            error_dialog = QtWidgets.QErrorMessage()
            error_dialog.showMessage("Password cannot be empty.")
            error_dialog.exec_()
            return

        if not self.encrypt_radio.isChecked() and not self.decrypt_radio.isChecked():
            error_dialog = QtWidgets.QErrorMessage()
            error_dialog.showMessage("Please select an operation.")
            error_dialog.exec_()
            return

        if savedir and not os.path.exists(savedir):
            error_dialog = QtWidgets.QErrorMessage()
            error_dialog.showMessage("Save directory does not exist.")
            error_dialog.exec_()
            return

        if self.encrypt_radio.isChecked():
            self.encrypt(filename, password)
            self.log_operation(filename, password, savedir, "Encrypt")

        if self.decrypt_radio.isChecked():
            self.decrypt(filename, password)
            self.log_operation(filename, password, savedir, "Decrypt")



    def log_operation(self, path, password, savedir, operation):
        log_path = os.path.join(savedir, "log.txt")
        if os.path.exists(log_path):
            with open(log_path, 'r') as log_file:
                log_content = log_file.read()
        else:
            log_content = ""
        with open(log_path, 'a') as log_file:
            log_file.write(f"{datetime.datetime.now()} - {operation} operation on {path} with password: {password}\n")
            log_file.write(log_content)


    def encrypt(self, path, password):
        # Generate a key from the password
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        # Convert the password to bytes before using it with PBKDF2HMAC.derive()
        key_material = bytes(password, 'utf-8')
        key = base64.urlsafe_b64encode(kdf.derive(key_material))

        # Encrypt the file or folder
        num_files_processed = 0
        fernet = Fernet(key)
        if os.path.isfile(path):
            with open(path, 'rb') as file:
                file_data = file.read()
            encrypted_data = fernet.encrypt(file_data)

            # Write the encrypted data to a new file
            encrypted_file_path = path + '.encrypted'
            with open(encrypted_file_path,'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            #remove the original file
            os.remove(path)

            num_files_processed += 1
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as current_file:
                        file_data = current_file.read()
                    encrypted_data = fernet.encrypt(file_data)
                    encrypted_file_path = file_path + '.encrypted'
                    with open(encrypted_file_path, 'wb') as encrypted_file:
                        encrypted_file.write(encrypted_data)
                    #remove the original file
                    os.remove(file_path)

                    num_files_processed += 1
        else:
            error_dialog = QtWidgets.QErrorMessage()
            error_dialog.setText("The specified path is not a file or folder.")
            error_dialog.show()
            return

        if num_files_processed > 2:
            success_dialog = QtWidgets.QMessageBox()
            success_dialog.setText("Files encrypted successfully!")
            success_dialog.exec_()
        else :
            success_dialog = QtWidgets.QMessageBox()
            success_dialog.setText("File encrypted successfully!")
            success_dialog.exec_()    
        return


    def decrypt(self, path, password):
        # Generate a key from the password
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key_material = bytes(password, 'utf-8')
        key = base64.urlsafe_b64encode(kdf.derive(key_material))

        # Decrypt the file or folder
        num_files_processed = 0
        fernet = Fernet(key)
        if os.path.isfile(path) and path.endswith('.encrypted'):
            with open(path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
            decrypted_data = fernet.decrypt(encrypted_data)

            # Write the decrypted data to a new file
            decrypted_file_path = os.path.splitext(path)[0]
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            #remove the original file
            os.remove(path)

            num_files_processed += 1
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith('.encrypted'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'rb') as current_file:
                            encrypted_data = current_file.read()
                        decrypted_data = fernet.decrypt(encrypted_data)
                        decrypted_file_path = os.path.splitext(file_path)[0]
                        with open(decrypted_file_path, 'wb') as decrypted_file:
                            decrypted_file.write(decrypted_data)
                        #remove the original file
                        os.remove(file_path)

                        num_files_processed += 1
        else:
            error_dialog = QtWidgets.QErrorMessage()
            error_dialog.showMessage("The specified path is not a .encrypted file or folder.")
            error_dialog.show()
            return

        if num_files_processed > 2:
            success_dialog = QtWidgets.QMessageBox()
            success_dialog.setText("Files decrypted successfully!")
            success_dialog.exec_()
        else :
            success_dialog = QtWidgets.QMessageBox()
            success_dialog.setText("File decrypted successfully!")
            success_dialog.exec_()            
        return


        
if __name__ == '__main__':
    app = QtWidgets.QApplication([])
    window = CryptoApp()
    app.exec_()
