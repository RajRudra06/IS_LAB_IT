# Simple Menu-Driven Program in Python

# Function to show menu
def menu():
    print("\n=== MENU ===")
    print("1. Option 1")
    print("2. Option 2")
    print("3. Option 3")
    print("4. Quit")

# Main program
while(1):   # infinite loop (runs until user chooses to exit)
    menu()  # show menu
    choice = input("Enter your choice: ").strip()   # take input from user

    if choice == '1':
        print("You selected Option 1")
        # call your function here, e.g., rail_fence_encrypt()
    elif choice == '2':
        print("You selected Option 2")
        # call another function
    elif choice == '3':
        print("You selected Option 3")
        # call another function
    elif choice == '4':
        print("Exiting program...")
        break   # break exits the while(1) loop
    else:
        print("Invalid choice, please try again.")
