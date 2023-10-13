from tkinter import *

WIDTH, HEIGHT = 700,500
def main_window():

	root = Tk()
	root.title("bhztk-aes")
	root.geometry(f"{WIDTH}x{HEIGHT}")


	enc_frame = LabelFrame(root,text="Encryption")

	keylbl = Label(enc_frame,justify="left", anchor="w",     text="Key")
	headerlbl = Label(enc_frame,justify="left", anchor="w",  text="Header")
	noncelbl = Label(enc_frame,justify="left", anchor="w",   text="Nonce")
	datalbl = Label(enc_frame,justify="left", anchor="w",    text="Data")
	filepathlbl = Label(enc_frame,justify="left", anchor="w",text="Filepath")
	maclenlbl = Label(enc_frame,justify="left", anchor="w",  text="Maclen")

	key_entry = Entry(enc_frame,width=50)
	header_entry = Entry(enc_frame,width=50)
	nonce_entry = Entry(enc_frame,width=50)
	data_entry = Entry(enc_frame,width=50)
	filepath_entry = Entry(enc_frame,width=50)
	maclen_entry = Entry(enc_frame,width=50)

	output_enc_label = LabelFrame(root,text="Encryption Output Window")
	text_output = Text(output_enc_label,height=10,width=50)


	enc_frame.place(x=10,y=10)
	key_entry.grid(row=0,column=1)
	header_entry.grid(row=1,column=1)
	nonce_entry.grid(row=2,column=1)
	data_entry.grid(row=3,column=1)
	filepath_entry.grid(row=4,column=1)
	maclen_entry.grid(row=5,column=1)
	keylbl.grid(sticky = W,row=0,column=0)
	headerlbl.grid(sticky = W,row=1,column=0)
	noncelbl.grid(sticky = W,row=2,column=0)
	datalbl.grid(sticky = W,row=3,column=0)
	filepathlbl.grid(sticky = W,row=4,column=0)
	maclenlbl.grid(sticky = W,row=5,column=0)


	output_enc_label.place(x=10,y=160)
	text_output.pack()


	root.mainloop()
if __name__ == '__main__':
	main_window()