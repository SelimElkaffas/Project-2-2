import tkinter as tk
import sys
import os

def test_window():
    try:
        print("Creating root window...")
        root = tk.Tk()
        print("Root window created successfully")
        
        # Make window more visible
        root.title("TEST WINDOW - LOOK FOR THIS")
        root.geometry("400x300")
        root.configure(bg='red')  # Bright red background
        root.attributes('-topmost', True)  # Make window stay on top
        print("Window geometry set")
        
        label = tk.Label(root, 
                        text="IF YOU CAN SEE THIS RED WINDOW,\nTkinter is working correctly!",
                        bg='red',
                        fg='white',
                        font=('Arial', 16, 'bold'))
        label.pack(pady=20)
        print("Label created and packed")
        
        button = tk.Button(root, 
                          text="CLOSE THIS WINDOW",
                          command=root.destroy,
                          bg='white',
                          font=('Arial', 12, 'bold'))
        button.pack(pady=10)
        print("Button created and packed")
        
        # Try to bring window to front
        root.lift()
        root.attributes('-topmost', True)
        root.after_idle(root.attributes, '-topmost', False)
        
        print("Starting mainloop...")
        root.mainloop()
        print("Mainloop ended")
    except Exception as e:
        print(f"Error in test_window: {str(e)}")
        print(f"Python version: {sys.version}")
        print(f"Current working directory: {os.getcwd()}")
        raise

if __name__ == "__main__":
    print("Testing tkinter...")
    print(f"Python executable: {sys.executable}")
    print(f"Display environment variable: {os.environ.get('DISPLAY', 'Not set')}")
    test_window() 