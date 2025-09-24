def collatz(number):
    """Return the next number in the Collatz sequence."""
    if number % 2 == 0:  # even
        result = number // 2
    else:  # odd
        result = 3 * number + 1
    print(result, end=' ')
    return result


def main():
    while True:
        try:
            # Ask user for input
            number = int(input("Enter number:\n"))
            print(number, end=' ')
            while number != 1:
                number = collatz(number)
            break  # exit loop once sequence reaches 1
        except ValueError:
            print("Error: You must enter an integer.")


if __name__ == "__main__":
    main()
