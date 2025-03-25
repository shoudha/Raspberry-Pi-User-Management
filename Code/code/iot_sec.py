from getpass import getpass
from pathlib import Path
from Crypto.Cipher import AES
from pandas import DataFrame
import re
from tkinter import *
from tkinter import ttk

key = b'1234567890qwerty'  # size = 16

class Encryptor:
    """Encryptor class for encryption and decryption."""

    def __init__(self, key):
        """Class Initialization."""
        self.key = key
        self.passFile = '../bin/passwords.txt'
        self.roleFile = '../bin/roles.txt'
        self.dataFile = '../data/data.csv'

    # Function for padding message
    def _padding(self, message):
        """
        Padding message with addition character.

        Returns:
            Padded message (str)
        """
        padded_msg = message + '$' * ((16 - len(message)) % 16)
        return(padded_msg)

    # Function for unpadding message
    def _unpadding(self, paded_message):
        """
        Unpadding message with addition character.

        Returns:
            Unpadded message (str)
        """
        # Remove '$' to unpad
        unpadded_msg = paded_message.replace('$', '')
        return(unpadded_msg)

    # Function for message encryption
    def encrypt(self, message, key):
        """
        Encrypt data.

        Returns:
            encrypted data (byte)
        """
        # Pad the message
        message = self._padding(message)
        # Create cipher object for encryption
        cipher = AES.new(key, mode=AES.MODE_ECB)
        # Encrypt
        encrypted_text = cipher.encrypt(message)
        return encrypted_text

    # Function to read file content and encrypt it's contents
    def encrypt_file(self, file_name, data=False, print_data=False):
        """
        Encrypt file.

        Returns:
            None
        """
        # If data is not passed
        if not data:
            # Open the file to be encrypted
            with open(file_name, 'r') as f:
                # Read file content
                file_content = f.read()
                # Check if data needs to be printed
                if print_data:
                    print(file_content)
                    print(file_name)
        # If data is passed in the file_name
        else:
            file_content = file_name

        # Encrypt file content
        encrypted_file_data = self.encrypt(file_content, self.key)
        # Write the encrypted content
        with open(file_name + '.enc', 'wb') as f:
            f.write(encrypted_file_data)

    # Function for message decryption
    def decrypt(self, cipher_text, key):
        """
        Decrypt data.

        Returns:
            decrypted data (byte)
        """
        # Create cipher object
        cipher = AES.new(key)
        # Decrypt cipher text
        plain_text = cipher.decrypt(cipher_text).decode('utf-8')
        # Unpad and return decrypted text
        return self._unpadding(plain_text)

    # Function for file decryption
    def decrypt_file(self, filename, return_data=False, print_data=True):
        """
        Decrypt File.

        Returns:
            None
        """
        # Read the encrypted passwords file
        with open(filename + '.enc', 'rb') as f:
            encrypted_content = f.read()
        # decrypt the file content
        decrypted = self.decrypt(encrypted_content, self.key)
        if return_data:
            return decrypted
        if print_data:
            print(decrypted)

    def check_user(self, username, password):
        """
        Authenticate user.

        Returns:
            Group Name or 0
        """
        group = 0
        # Decrypt the password file
        data = self.decrypt_file(self.passFile, return_data=True)

        # Find the group of the given username
        for line in data.strip().split('\n'):
            usr, pwd, usr_group = line.split(' ')
            if usr == username and pwd == password:
                group = usr_group
        return group

    def get_roles(self, group):
        """
        Return the access allowed for the group.

        Returns:
            List of allowed access
        """
        data = self.decrypt_file(self.roleFile, return_data=True)

        for line in data.split('\n'):
            temp_line = line.split('=')
            if group == temp_line[0].strip():
                access = temp_line[1]
                return [row.strip() for row in access.split(',')]
        return 0

    def get_data(self, can_be_accessed):
        """
        Print the allowed data from the data file.

        Returns:
            Data
        """
        data = self.decrypt_file(self.dataFile, return_data=True)
        data = data.strip().split("\n")
        data = [data[i].split(",") for i in range(len(data))]
        headers = data.pop(0)
        data = DataFrame(data, columns=headers)
        return(data)
        
        
def forgetFrames():

    admin_ctrl_frame.grid_forget()
    edit_admin_ctrl.grid_forget()
    add_usr_frame.grid_forget()
    mod_usr_frame.grid_forget()
    add_grp_frame.grid_forget()
    mod_grp_frame.grid_forget()
    
        # Function to execute when access requested
def LogIn():

    # Verify if the username and password are valid
    group = enc.check_user(usr_entry.get(), pw_entry.get())

    if group != 0:

        logIn_btn["state"] = "disabled"
        logOut_btn["state"] = "normal"

        #######################################################
        # ############ SHOW USER INFO AND DATA INFO
        #######################################################

        # ####### User information frame
        user_name = usr_entry.get()
        user_group = group

        # ####### Data view frame
        if not Path(enc.dataFile + '.enc').is_file():
            print('File does not exist')
            exit()

        can_be_accessed = enc.get_roles(group)
        data_from_database = enc.get_data(can_be_accessed)

        data_table["columns"] = tuple(e for e in range(len(can_be_accessed)))
        data_table['show'] = 'headings'

        for i in range(len(can_be_accessed)):
            data_table.column(i, stretch=0)
            data_table.heading(i, text=can_be_accessed[i], anchor='w')

        cols_wo_first = list(data_from_database[can_be_accessed].itertuples(index=False, name=None))

        for i in range(len(data_from_database[can_be_accessed[0]])):

            data_table.insert('', str(i), 'row' + str(i), text='',\
                              values=cols_wo_first[i])

        if group == 'admin':

            #######################################################
            # ############ SHOW ADDITIONAL FRAMES FOR ADMIN CONTROL
            #######################################################

            # Frame widget
            admin_ctrl_frame.grid(row=3, column=0, padx=10, pady=10, sticky=W+E+N+S)
            edit_admin_ctrl.grid(row=3, column=1, padx=10, pady=10, columnspan=100, sticky=W+E+N+S)

            # Normal buttons for control panel
            add_user_btn["state"] = "normal"
            mod_user_btn["state"] = "normal"
            add_grp_btn["state"] = "normal"
            mod_grp_btn["state"] = "normal"

    else:
        #######################################################
        # ############ SHOW USER INFO AND DATA INFO
        #######################################################

        # ####### User information frame
        user_name = "User not found"
        user_group = "Group not found"

        # ####### Data view frame
        data_table["columns"] = tuple(e for e in range(1))
        data_table['show'] = 'headings'

        for i in range(1):
            data_table.column(i, stretch=0)
            data_table.heading(i, text=' ', anchor='w')

        for i in data_table.get_children():
            data_table.delete(i)

        #######################################################
        # ############ SHOW ADDITIONAL FRAMES FOR ADMIN CONTROL
        #######################################################

        forgetFrames()

    # ####### User information frame
    usr_name_text.set(user_name)
    usr_role_text.set(user_group)
# Function to clear all data when logged out
def LogOut():

    logIn_btn["state"] = "normal"
    logOut_btn["state"] = "disabled"

    #######################################################
    # ############ SHOW USER INFO AND DATA INFO
    #######################################################

    # ####### User information frame
    usr_name_text.set(" ")
    usr_role_text.set(" ")

    # ####### Data view frame
    data_table["columns"] = tuple(e for e in range(1))
    data_table['show'] = 'headings'

    for i in range(1):
        data_table.column(i, stretch=0)
        data_table.heading(i, text=' ', anchor='w')

    for i in data_table.get_children():
        data_table.delete(i)

    #######################################################
    # ############ SHOW ADDITIONAL FRAMES FOR ADMIN CONTROL
    #######################################################

    forgetFrames()

# Function to clear all data when logged out
def addUser():

    add_user_btn["state"] = "disabled"
    mod_user_btn["state"] = "normal"
    add_grp_btn["state"] = "normal"
    mod_grp_btn["state"] = "normal"

    def saveUsr():
        usr_new = add_usr_entry.get()
        pw_new = add_pw_entry.get()
        grp_new = add_grp_entry.get()

        check = 0
        for header in headers:
            check = check + au_dict["var_" + header].get()

        if bool(usr_new.strip()) and bool(pw_new.strip()) and bool(grp_new.strip()) and check != 0:
            role_au = ""
            n_roles = 0
            for header in headers:
                if au_dict["var_" + header].get():
                    if n_roles == 0:
                        role_au = role_au + header
                    else:
                        role_au = role_au + ", " + header
                    n_roles = n_roles + 1

            add_data = usr_new + " " + pw_new + " " + grp_new
            add_role = role_au

            group = add_data.strip().split()[-1]
            rdata = enc.decrypt_file(enc.roleFile, return_data=True)
            role_data = rdata.split('\n')
            role_data.append(group + " = " + add_role)

            data = '\n'.join(role_data)
            with open(enc.roleFile, 'w+') as f:
                f.write(data)
            enc.encrypt_file(enc.roleFile)
            Path(enc.roleFile).unlink()

            data = enc.decrypt_file(enc.passFile, return_data=True)
            data = data.split('\n')
            modified = False
            if len(add_data.split()) != 3:
                print('ERROR: Details not added properly. Try again!')
                exit()
            for i in range(len(data)):
                if add_data.split()[0] in data[i]:
                    data[i] = add_data
                    modified = True
            if not modified:
                data.append(add_data)
            data = '\n'.join(data)
            with open(enc.passFile, 'w+') as f:
                f.write(data)
            enc.encrypt_file(enc.passFile)
            Path(enc.passFile).unlink()

    # Hide the default frame
    edit_admin_ctrl.grid_forget()

    # forget other admin control frames
    add_grp_frame.grid_forget()
    mod_usr_frame.grid_forget()
    mod_grp_frame.grid_forget()

    add_usr_frame.grid(row=3, column=1, padx=10, pady=10, columnspan=100, sticky=W+E+N+S)

    # Label for user name and password
    add_usr_label = Label(add_usr_frame, text="Username:  ", bg="white")
    add_usr_label.grid(row=0, column=0, sticky=W)
    add_pw_label = Label(add_usr_frame, text="Password:  ", bg="white")
    add_pw_label.grid(row=1, column=0, sticky=W)
    add_grp_label = Label(add_usr_frame, text="Group name:  ", bg="white")
    add_grp_label.grid(row=2, column=0, sticky=W)

    # Input box for username and password
    add_usr_entry = Entry(add_usr_frame)
    add_usr_entry.grid(row=0, column=1, pady=2)
    add_pw_entry = Entry(add_usr_frame)
    add_pw_entry.grid(row=1, column=1, pady=2)
    add_pw_entry.config(show="*")
    add_grp_entry = Entry(add_usr_frame)
    add_grp_entry.grid(row=2, column=1, pady=2)

    # Label for role names
    clmn_label = Label(add_usr_frame, text="Select Role:  ", bg="white")
    clmn_label.grid(row=3, column=0, sticky=W)

    # Checkbox to select user roles
    headers = enc.get_roles('admin')

    au_dict = {}
    row_pos = 4
    for header in headers:

        au_dict["var_" + header] = IntVar()
        l = Checkbutton(add_usr_frame, text=header, variable=au_dict["var_" + header],\
                        bg="white", highlightthickness=0)

        l.grid(row=row_pos, column=0, sticky=W)
        row_pos += 1

    # Save user button
    save_usr_btn = Button(add_usr_frame, text="Save user", command=saveUsr, bg="white")
    save_usr_btn.grid(row=0, column=2, columnspan=2, sticky=W + E + N + S, padx=10)

# Function to clear all data when logged out
def modUser():

    add_user_btn["state"] = "normal"
    mod_user_btn["state"] = "disabled"
    add_grp_btn["state"] = "normal"
    mod_grp_btn["state"] = "normal"

    def modUsr():
        usr_mod = mod_usr_entry.get()
        pw_mod = mod_pw_entry.get()
        grp_mod = mod_grp_entry.get()

        if bool(usr_mod.strip()) and bool(pw_mod.strip()) and bool(grp_mod.strip()):

            add_data = usr_mod + " " + pw_mod + " " + grp_mod

            data = enc.decrypt_file(enc.passFile, return_data=True)
            data = data.split('\n')
            modified = False
            if len(add_data.split()) != 3:
                print('ERROR: Details not added properly. Try again!')
                exit()
            for i in range(len(data)):
                if add_data.split()[0] in data[i]:
                    data[i] = add_data
                    modified = True
            if not modified:
                data.append(add_data)
            data = '\n'.join(data)
            with open(enc.passFile, 'w+') as f:
                f.write(data)
            enc.encrypt_file(enc.passFile)
            Path(enc.passFile).unlink()

    # Hide the default frame
    edit_admin_ctrl.grid_forget()

    # forget other admin control frames
    add_usr_frame.grid_forget()
    add_grp_frame.grid_forget()
    mod_grp_frame.grid_forget()

    mod_usr_frame.grid(row=3, column=1, padx=10, pady=10, columnspan=100, sticky=W+E+N+S)

    # Label for user name and password
    mod_usr_label = Label(mod_usr_frame, text="Username:  ", bg="white")
    mod_usr_label.grid(row=0, column=0, sticky=W)
    mod_pw_label = Label(mod_usr_frame, text="Password:  ", bg="white")
    mod_pw_label.grid(row=1, column=0, sticky=W)
    mod_pw_label = Label(mod_usr_frame, text="Group name:  ", bg="white")
    mod_pw_label.grid(row=2, column=0, sticky=W)

    # Input box for username and password
    mod_usr_entry = Entry(mod_usr_frame)
    mod_usr_entry.grid(row=0, column=1, pady=2)
    mod_pw_entry = Entry(mod_usr_frame)
    mod_pw_entry.grid(row=1, column=1, pady=2)
    mod_pw_entry.config(show="*")
    mod_grp_entry = Entry(mod_usr_frame)
    mod_grp_entry.grid(row=2, column=1, pady=2)

    # Save user button
    update_usr_btn = Button(mod_usr_frame, text="Update user", command=modUsr, bg="white")
    update_usr_btn.grid(row=0, column=2, columnspan=2, sticky=W + E + N + S, padx=10)

# Function to clear all data when logged out
def addGroup():

    add_user_btn["state"] = "normal"
    mod_user_btn["state"] = "normal"
    add_grp_btn["state"] = "disabled"
    mod_grp_btn["state"] = "normal"

    def saveGrp():

        new_grp = grp_entry.get()

        check = 0
        for header in headers:
            check = check + ag_dict["var_" + header].get()

        if check != 0:
            if bool(new_grp.strip()):

                role_ag = " "
                n_roles = 0
                for header in headers:
                    if ag_dict["var_" + header].get():
                        if n_roles == 0:
                            role_ag = role_ag + header
                        else:
                            role_ag = role_ag + ", " + header
                        n_roles = n_roles + 1

                add_data = new_grp + " =" + role_ag

                data = enc.decrypt_file(enc.roleFile, return_data=True)
                data = data.split('\n')
                modified = False
                regex_match_1 = re.compile('.*=.*')
                regex_match_2 = re.compile('.*=.*,.*')
                match_1 = regex_match_1.match(add_data)
                match_2 = regex_match_2.match(add_data)
                if (match_1 is None and match_2 is None):
                    print('ERROR: Details not added properly. Try Again!')
                    exit()
                for i in range(len(data)):
                    if add_data.split()[0] in data[i]:
                        data[i] = add_data  # replace that line with new data
                        modified = True
                if not modified:
                    data.append(add_data)
                data = '\n'.join(data)
                with open(enc.roleFile, 'w+') as f:
                    f.write(data)
                enc.encrypt_file(enc.roleFile)
                Path(enc.roleFile).unlink()

    # Hide the default frame
    edit_admin_ctrl.grid_forget()

    # forget other admin control frames
    add_usr_frame.grid_forget()
    mod_usr_frame.grid_forget()
    mod_grp_frame.grid_forget()

    add_grp_frame.grid(row=3, column=1, padx=10, pady=10, columnspan=100, sticky=W+E+N+S)

    # Label for group name
    grp_label = Label(add_grp_frame, text="Group Name:  ", bg="white")
    grp_label.grid(row=0, column=0, sticky=W)

    # Input box for Group Name
    grp_entry = Entry(add_grp_frame)
    grp_entry.grid(row=0, column=1)

    # Label for column names
    clmn_label = Label(add_grp_frame, text="Select Role:  ", bg="white")
    clmn_label.grid(row=1, column=0, sticky=W)

    # Checkbox for columns
    headers = enc.get_roles('admin')

    ag_dict = {}
    row_pos = 2
    for header in headers:

        ag_dict["var_" + header] = IntVar()
        l = Checkbutton(add_grp_frame, text=header, variable=ag_dict["var_" + header],\
                        bg="white", highlightthickness=0)

        l.grid(row=row_pos, column=0, sticky=W)
        row_pos += 1

    save_grp_btn = Button(add_grp_frame, text="Save group", command=saveGrp, bg="white")
    save_grp_btn.grid(row=0, column=2, columnspan=2, sticky=W + E + N + S, padx=10)

# Function to clear all data when logged out
def modGroup():

    add_user_btn["state"] = "normal"
    mod_user_btn["state"] = "normal"
    add_grp_btn["state"] = "normal"
    mod_grp_btn["state"] = "disabled"

    def updateGrp():

        new_grp = grp_entry.get()

        check = 0
        for header in headers:
            check = check + ug_dict["var_" + header].get()

        if check != 0:
            if bool(new_grp.strip()):

                role_ug = " "
                n_roles = 0
                for header in headers:
                    if ug_dict["var_" + header].get():
                        if n_roles == 0:
                            role_ug = role_ug + header
                        else:
                            role_ug = role_ug + ", " + header
                        n_roles = n_roles + 1

                add_data = new_grp + " =" + role_ug

                data = enc.decrypt_file(enc.roleFile, return_data=True)
                data = data.split('\n')
                modified = False
                regex_match_1 = re.compile('.*=.*')
                regex_match_2 = re.compile('.*=.*,.*')
                match_1 = regex_match_1.match(add_data)
                match_2 = regex_match_2.match(add_data)
                if (match_1 is None and match_2 is None):
                    print('ERROR: Details not added properly. Try Again!')
                    exit()
                for i in range(len(data)):
                    if add_data.split()[0] in data[i]:
                        data[i] = add_data  # replace that line with new data
                        modified = True
                if not modified:
                    data.append(add_data)
                data = '\n'.join(data)
                with open(enc.roleFile, 'w+') as f:
                    f.write(data)
                enc.encrypt_file(enc.roleFile)
                Path(enc.roleFile).unlink()

    # Hide the default frame
    edit_admin_ctrl.grid_forget()

    # forget other admin control frames
    add_usr_frame.grid_forget()
    mod_usr_frame.grid_forget()
    add_grp_frame.grid_forget()

    mod_grp_frame.grid(row=3, column=1, padx=10, pady=10, columnspan=100, sticky=W + E + N + S)

    # Label for group name
    grp_label = Label(mod_grp_frame, text="Group Name:  ", bg="white")
    grp_label.grid(row=0, column=0, sticky=W)

    # Input box for Group Name
    grp_entry = Entry(mod_grp_frame)
    grp_entry.grid(row=0, column=1)

    # Label for column names
    clmn_label = Label(mod_grp_frame, text="Select Role:  ", bg="white")
    clmn_label.grid(row=1, column=0, sticky=W)

    # Checkbox for columns
    headers = enc.get_roles('admin')

    ug_dict = {}
    row_pos = 2
    for header in headers:

        ug_dict["var_" + header] = IntVar()
        l = Checkbutton(mod_grp_frame, text=header, variable=ug_dict["var_" + header],\
                        bg="white", highlightthickness=0)
        l.grid(row=row_pos, column=0, sticky=W)
        row_pos += 1

    update_grp_btn = Button(mod_grp_frame, text="Update group", command=updateGrp, bg="white")
    update_grp_btn.grid(row=0, column=2, columnspan=2, sticky=W+E+N+S, padx=10)


# Create Encryptor class

if __name__ == '__main__':
   
    enc = Encryptor(key)
            
    if not Path('../bin').is_dir():
        
        if not Path(enc.dataFile).is_file():
            print('!!! Please save your data.csv file in here !!!')
            exit()
        else:
            enc.encrypt_file(enc.dataFile)
        
        with open(enc.dataFile, 'r') as f:
            # Read file content
            data = f.read()
            
        data = data.strip().split("\n")
        data = [data[i].split(",") for i in range(len(data))]
        headers = data.pop(0)
        
        # initialize an empty string 
        admin_roles = str(headers[0])
        # convert data headers to string   
        for header in headers[1:]:
            admin_roles = admin_roles + ", " + header
        
        Path('../bin').mkdir()
        username = input('Set Admin Username: ')
        password = getpass('Set Admin Password: ')
        with open(enc.passFile, 'w+') as f:
            f.write(username + ' ' + password + ' admin')
        enc.encrypt_file(enc.passFile)
        Path(enc.passFile).unlink()
        
        with open(enc.roleFile, 'w+') as f:
            f.write('admin = ' + admin_roles)
        enc.encrypt_file(enc.roleFile)
        Path(enc.roleFile).unlink()
        
    ########################################
    # Start Tkinter
    ########################################
    root = Tk()
    root.title("User Management System")
    root.configure(bg='white')
    
    ########################################
    # Title/Heading
    ########################################
    
    title1 = Label(root,\
                  text="IoT Device and User Management System",\
                  bg="white",\
                  font=("Calibri", 15))
    title1.grid(row=0, column=0, padx=5, pady=5, sticky=W, columnspan=2)
    
    ########################################
    # User access request frame
    ########################################
    
    # Frame widget
    frame_login = LabelFrame(root, text="User login", padx=20, pady=20, bg="white")
    frame_login.grid(row=1, column=0, padx=10, pady=10, sticky=W + E + N + S)
    
    # Label for username and password
    usr_label = Label(frame_login, text="Username  ", bg="white")
    usr_label.grid(row=0, column=0, sticky=W)
    
    pw_label = Label(frame_login, text="Password  ", bg="white")
    pw_label.grid(row=1, column=0, sticky=W)
    
    # Input boxes for username and password
    usr_entry = Entry(frame_login)
    usr_entry.grid(row=0, column=1, pady=3)
    
    pw_entry = Entry(frame_login)
    pw_entry.config(show="*")
    pw_entry.grid(row=1, column=1, pady=3)
    
    # Button to request access and sign off
    logIn_btn = Button(frame_login, text="Log In", command=LogIn, bg="white")
    logIn_btn.grid(row=2, column=0, columnspan=2, sticky=W+E+N+S, pady=5)
    
    logOut_btn = Button(frame_login, text="Log Out", command=LogOut, state="disabled", bg="white")
    logOut_btn.grid(row=3, column=0, columnspan=2, sticky=W+E+N+S, pady=5)
    
    ########################################
    # User Information frame
    ########################################
    
    # Frame widget
    user_info = LabelFrame(root, text="User Information", padx=20, pady=20, bg="white")
    user_info.grid(row=2, column=0, padx=10, pady=10, sticky=W+E+N+S)
    
    # Label for username and role information
    usr_info_label = Label(user_info, text="Username: ", bg="white")
    usr_info_label.grid(row=0, column=0, sticky=W)
    
    role_info_label = Label(user_info, text="User group: ", bg="white")
    role_info_label.grid(row=1, column=0, sticky=W)
    
    # Username and user role from database
    usr_name_text = StringVar()
    usr_name_text.set(" ")
    
    usr_role_text = StringVar()
    usr_role_text.set(" ")
    
    usr_from_database = Label(user_info, textvariable=usr_name_text, bg="white")
    usr_from_database.grid(row=0, column=1, sticky=W)
    
    role_from_database = Label(user_info, textvariable=usr_role_text, bg="white")
    role_from_database.grid(row=1, column=1, sticky=W)
    
    ########################################
    # Data view frame
    ########################################
    
    # Frame widget
    data_frame = LabelFrame(root, text="IoT Sensor Data", padx=20, pady=20, bg="white")
    data_frame.grid(row=1, column=1, padx=10, pady=10, sticky=W + E + N + S, columnspan=5, rowspan=2)
    
    data_table = ttk.Treeview(data_frame)
    data_table.grid(row=0, column=0, sticky=W)
    
    ########################################
    # ADMIN CONTROL FRAME
    ########################################
    
    # Frame widget
    admin_ctrl_frame = LabelFrame(root, text="Admin Control Panel", padx=20, pady=20, bg="white")
    
    # Button to request access and sign off
    add_user_btn = Button(admin_ctrl_frame, text="Add User", command=addUser, bg="white")
    add_user_btn.grid(row=0, column=0, columnspan=3, sticky=W + E + N + S, pady=2)
    
    mod_user_btn = Button(admin_ctrl_frame, text="Modify User", command=modUser, bg="white")
    mod_user_btn.grid(row=1, column=0, columnspan=2, sticky=W + E + N + S, pady=2)
    
    add_grp_btn = Button(admin_ctrl_frame, text="Add Group", command=addGroup, bg="white")
    add_grp_btn.grid(row=2, column=0, columnspan=2, sticky=W + E + N + S, pady=2)
    
    mod_grp_btn = Button(admin_ctrl_frame, text="Modify Group", command=modGroup, bg="white")
    mod_grp_btn.grid(row=3, column=0, columnspan=2, sticky=W + E + N + S, pady=2)
    
    ########################################
    # Edit Frame for admin control panel
    ########################################
    
    # Frame widget
    edit_admin_ctrl = LabelFrame(root, text="Edit Admin Control", padx=20, pady=20, bg="white")
    
    ########################################
    # Add User Frame
    add_usr_frame = LabelFrame(root, text="Add user", padx=20, pady=20, bg="white")
    
    ########################################
    # Mod User Frame
    mod_usr_frame = LabelFrame(root, text="Edit user", padx=20, pady=20, bg="white")
    
    ########################################
    # Add Group Frame
    add_grp_frame = LabelFrame(root, text="Add Group", padx=20, pady=20, bg="white")
    
    ########################################
    # Mod Group Frame
    mod_grp_frame = LabelFrame(root, text="Edit Group", padx=20, pady=20, bg="white")
    
    root.mainloop()
