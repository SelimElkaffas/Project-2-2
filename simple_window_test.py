import tkinter as tk
from tkinter import messagebox
import os
import sys

def show_info():
    info = f"""
    Python Version: {sys.version}
    Working Directory: {os.getcwd()}
    Display: {os.environ.get('DISPLAY', 'Not Set')}
    Username: {os.environ.get('USERNAME', 'Not Set')}
    """
    messagebox.showinfo("System Info", info)

# Create the main window
root = tk.Tk()
root.title("Simple Window Test")
root.geometry("400x300+100+100")  # width x height + x + y
root.configure(bg='yellow')  # Very visible background

# Add some visible elements
label = tk.Label(root, 
                 text="If you can see this YELLOW window\nclick the button below!",
                 bg='yellow',
                 font=('Arial', 14, 'bold'))
label.pack(pady=20)

# Add a button
button = tk.Button(root,
                   text="Click Me!",
                   command=show_info,
                   bg='red',
                   fg='white',
                   font=('Arial', 12, 'bold'))
button.pack(pady=20)

# Force window to front
root.lift()
root.attributes('-topmost', True)
root.after_idle(root.attributes, '-topmost', False)

print("Window created and configured")
print("Starting mainloop...")
root.mainloop()
print("Mainloop ended") 