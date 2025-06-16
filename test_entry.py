import tkinter as tk

root = tk.Tk()
root.geometry("300x100")
root.title("Tkinter Test")
root.configure(bg="white")

label = tk.Label(root, text="Type below:", bg="white", fg="black")
label.pack(pady=(10,0))

e = tk.Entry(root, bg="white", fg="black")
e.pack(pady=10)
e.focus_set()

root.mainloop()