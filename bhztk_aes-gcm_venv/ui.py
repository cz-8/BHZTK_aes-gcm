from tkinter import *
import os
from tkinter import filedialog

WIDTH, HEIGHT = 700,500
def frontend_encrypt(key_entry,header_entry,data_entry,filepath_entry,maclen_entry,outputpathlbl):

	key = key_entry.get()
	header = header_entry()
	data = data_entry()
	filepath = filepath.get()
	maclen = maclen_entry()
	outputpath = outputpathlbl.get()

	print(key,header,data,filepath,maclen,outputpath)

def file_explorer(placer,config_label):

	if placer == 1:

		FILE_PATH = filedialog.askopenfilename(filetypes=[("All Files", "*.*")]) #IMPORTANT_VAR

		if FILE_PATH != "":
			config_label.set(FILE_PATH)

	elif placer == 2:

		FILE_PATH = filedialog.askopenfilename(filetypes=[("Bhz Enc objects", "*.BHZENCOBJ; *.BHZCOMPENCOBJ")]) #IMPORTANT_VAR

		if FILE_PATH != "":
			config_label.set(FILE_PATH)


	elif placer == 3:

		OUTPUT_PATH = filedialog.askdirectory()

		if OUTPUT_PATH != "":
			config_label.set(OUTPUT_PATH)


def show_enc_frame(enc_frame,dec_frame):
	try:
		dec_frame.grid_forget()
	except:
		pass
	enc_frame.grid(row=3, column=0)

def show_dec_frame(enc_frame,dec_frame):
	try:
		enc_frame.grid_forget()
	except:
		pass
	dec_frame.grid(row=3, column=0)


def info_display(selec: int,root):

	if selec == 1:
		text1 = '''
# BHZTK_aes-gcm
library and cli tool to encrypt an decrypt files or strings using aes-gcm


tools:

gcc version 13.1.0 (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders)

Python 3.11.4 (tags/v3.11.4:d2340ef, Jun  7 2023, 05:45:37) [MSC v.1934 64 bit (AMD64)] on win32


                                    #input array

    # index      variable         type                        info

    #  0          = key            bytes            (len must be either 16 or 24 or 32 )

    #  1          = header         bytes            (optional, dont need to be unique)

    #  2          = data           bytes            (data to be encrypted, if size exceeds MAX_MEMORY_USAGE it will be encrypted in chunks)

    #  3          = nonce          bytes            (must be unique for every pair of message+key)

    #  4          = tag            bytes            (MAC tag)

    #  5          = mac len        int              ([>=4; >=16])

    #  6          = filename       str              (path of input file)

    #  7          = mode           str              (encryption = "enc"; decryption = "dec")

'''	
		top = Toplevel(root)
		top.geometry("500x400")
		top.title("Info")
		Label(top, text=text1,justify= LEFT).pack()

	elif selec == 2:
		top = Toplevel(root)
		top.geometry("500x400")
		top.title("Info")
		text1 = '''
variable_________________________info

key______________________________(len must be either 16 or 24 or 32 )

header___________________________(optional, dont need to be unique)

data_____________________________(data to be encrypted; if size exceeds MAX_MEMORY_USAGE it will be encrypted in chunks)

nonce____________________________(must be unique for every pair of message+key; if input is not given default=os.urandom(96))

tag______________________________(MAC tag, this is only needed for decryption with data)

mac_len__________________________([>=4; <= 16];, if input is not given, default=16)

filename_________________________(path of input file, if file is in working directory, onlyfilename is needed)

mode_____________________________(encryption = "enc"; decryption = "dec")
	   '''
		Label(top, text=text1,justify= LEFT).pack()



def main_window():

	root = Tk()
	root.title("bhztk-aes")
	root.geometry(f"{WIDTH}x{HEIGHT}")
	input_frame = LabelFrame(root,text="INPUT FORM")
	
	enc_frame = LabelFrame(input_frame, text="Encryption")

	keylbl = Label(enc_frame, justify="left", anchor="w", text="Key")
	headerlbl = Label(enc_frame, justify="left", anchor="w", text="Header")
	noncelbl = Label(enc_frame, justify="left", anchor="w", text="Nonce")
	datalbl = Label(enc_frame, justify="left", anchor="w", text="Data")
	filepathlbl = Label(enc_frame, justify="left", anchor="w", text="Filepath")
	maclenlbl = Label(enc_frame, justify="left", anchor="w", text="Maclen")
	outputpathlbl = Label(enc_frame, justify="left", anchor="w", text="Output Path")

	filepath_entry_var = StringVar(enc_frame,"")
	outputpath_entry_var = StringVar(enc_frame,f"{os.getcwd()}")

	filepath_button = Button(enc_frame,text="Select File",command=lambda: file_explorer(1,filepath_entry_var))

	filepath_button.grid(row=4,column=3)

	outputpath_button = Button(enc_frame,text="Select Path",command=lambda: file_explorer(3,outputpath_entry_var))

	outputpath_button.grid(row=6,column=3)

	key_entry = Entry(enc_frame, width=60)
	header_entry = Entry(enc_frame, width=60)
	nonce_entry = Entry(enc_frame, width=60)
	data_entry = Entry(enc_frame, width=60)
	filepath_entry = Entry(enc_frame, width=60,textvariable=filepath_entry_var)
	maclen_entry = Entry(enc_frame, width=60)
	outputpath_entry = Entry(enc_frame, width=60,textvariable=outputpath_entry_var)

	key_entry.grid(row=0, column=1)
	header_entry.grid(row=1, column=1)
	nonce_entry.grid(row=2, column=1)
	data_entry.grid(row=3, column=1)
	filepath_entry.grid(row=4, column=1)
	maclen_entry.grid(row=5, column=1)
	outputpath_entry.grid(row=6, column=1)

	keylbl.grid(sticky=W, row=0, column=0)
	headerlbl.grid(sticky=W, row=1, column=0)
	noncelbl.grid(sticky=W, row=2, column=0)
	datalbl.grid(sticky=W, row=3, column=0)
	filepathlbl.grid(sticky=W, row=4, column=0)
	maclenlbl.grid(sticky=W, row=5, column=0)
	outputpathlbl.grid(sticky=W, row=6, column=0)

	dec_frame = LabelFrame(input_frame, text="Decryption")

	keylbl_dec = Label(dec_frame, justify="left", anchor="w", text="Key")
	headerlbl_dec = Label(dec_frame, justify="left", anchor="w", text="Header")
	noncelbl_dec = Label(dec_frame, justify="left", anchor="w", text="Nonce")
	datalbl_dec = Label(dec_frame, justify="left", anchor="w", text="Data")
	filepathlbl_dec = Label(dec_frame, justify="left", anchor="w", text="Filepath")
	maclenlbl_dec = Label(dec_frame, justify="left", anchor="w", text="Maclen")
	outputpathlbl_dec = Label(dec_frame, justify="left", anchor="w", text="Output Path")
	taglbl_dec = Label(dec_frame, justify="left", anchor="w", text="Tag")

	filepath_entry_dec_var = StringVar(enc_frame,"")
	outputpath_entry_dec_var = StringVar(enc_frame,f"{os.getcwd()}")

	filepath_button_dec = Button(dec_frame,text="Select File",command=lambda: file_explorer(2,filepath_entry_dec_var))

	filepath_button_dec.grid(row=5,column=3)

	outputpath_button_dec = Button(dec_frame,text="Select Path",command=lambda: file_explorer(3,outputpath_entry_dec_var))

	outputpath_button_dec.grid(row=7,column=3)

	tag_entry_dec = Entry(dec_frame, width=60)
	key_entry_dec = Entry(dec_frame, width=60)
	header_entry_dec = Entry(dec_frame, width=60)
	nonce_entry_dec = Entry(dec_frame, width=60)
	data_entry_dec = Entry(dec_frame, width=60)
	filepath_entry_dec = Entry(dec_frame, width=60,textvariable=filepath_entry_dec_var)
	maclen_entry_dec = Entry(dec_frame, width=60)
	outputpath_entry_dec = Entry(dec_frame, width=60,textvariable=outputpath_entry_dec_var)

	keylbl_dec.grid(sticky=W, row=0, column=0)
	taglbl_dec.grid(sticky=W, row=1, column=0)  # Place the Tag label in between
	noncelbl_dec.grid(sticky=W, row=2, column=0)
	headerlbl_dec.grid(sticky=W, row=3, column=0)  # Shift Header below Tag
	datalbl_dec.grid(sticky=W, row=4, column=0)
	filepathlbl_dec.grid(sticky=W, row=5, column=0)
	maclenlbl_dec.grid(sticky=W, row=6, column=0)
	outputpathlbl_dec.grid(sticky=W, row=7, column=0)  # Adjust rows accordingly

	key_entry_dec.grid(row=0, column=1)
	tag_entry_dec.grid(row=1, column=1)  # Place the Tag entry in between
	nonce_entry_dec.grid(row=2, column=1)
	header_entry_dec.grid(row=3, column=1)  # Shift Header below Tag entry
	data_entry_dec.grid(row=4, column=1)
	filepath_entry_dec.grid(row=5, column=1)
	maclen_entry_dec.grid(row=6, column=1)
	outputpath_entry_dec.grid(row=7, column=1)  # Adjust rows accordingly

	

	config_choice = IntVar(input_frame, 1) #IMPORTANT_VAR

	C1 = Checkbutton(input_frame, text = "Data", variable = config_choice,onvalue = 1, offvalue = 0)
	C2 = Checkbutton(input_frame, text = "File", variable = config_choice,onvalue = 0, offvalue = 1)

	enc_button = Button(input_frame, text="Show Encryption Frame", command=lambda: show_enc_frame(enc_frame,dec_frame))
	dec_button = Button(input_frame, text="Show Decryption Frame", command=lambda: show_dec_frame(enc_frame,dec_frame))
	input_frame.place(x=10,y=10)
	enc_button.grid(row=0, column=0)
	dec_button.grid(row=1, column=0)
	C1.grid(row=0, column=1)
	C2.grid(row=1, column=1)

	info_frame = LabelFrame(root,text="Info")


	info_button_general = Button(info_frame,text="General 🛈",command=lambda: info_display(1,root))
	info_button_general.pack()
	info_button_general = Button(info_frame,text="Input     🛈",command=lambda: info_display(2,root))
	info_button_general.pack()

	info_frame.place(x=630,y=10)


	encrypt_button =  Button(root,text="Encrypt",command=lambda: frontend_encrypt(key_entry,header_entry,data_entry,filepath_entry,maclen_entry,outputpathlbl))






	root.mainloop()
if __name__ == '__main__':
	main_window()