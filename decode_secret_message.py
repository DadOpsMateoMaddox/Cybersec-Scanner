import requests
from bs4 import BeautifulSoup

def print_secret_message(doc_url):
    # Fetch the HTML content of the Google Document
    response = requests.get(doc_url)
    response.raise_for_status()  # Ensure the request was successful
    html_content = response.text

    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')

    # Find the table in the document
    table = soup.find('table')
    if not table:
        raise ValueError("No table found in the document.")

    # Initialize a list to store the extracted data
    data = []

    # Iterate over the rows of the table
    for row in table.find_all('tr')[1:]:  # Skip the header row
        cells = row.find_all('td')
        if len(cells) != 3:
            continue  # Skip rows that don't have exactly 3 cells
        try:
            x = int(cells[0].get_text(strip=True))
            char = cells[1].get_text(strip=True)
            y = int(cells[2].get_text(strip=True))
            data.append((x, y, char))
        except ValueError:
            continue  # Skip rows with invalid integer values

    if not data:
        raise ValueError("No valid data found in the table.")

    # Determine the size of the grid
    max_x = max(x for x, y, char in data)
    max_y = max(y for x, y, char in data)

    # Initialize the grid with spaces
    grid = [[' ' for _ in range(max_x + 1)] for _ in range(max_y + 1)]

    # Populate the grid with the characters
    for x, y, char in data:
        grid[y][x] = char

    # Print the grid
    for row in grid:
        print(''.join(row))

# Example usage:
doc_url = 'https://docs.google.com/document/d/e/2PACX-1vQGUck9HIFCyezsrBSnmENk5ieJuYwpt7YHYEzeNJkIb9OSDdx-ov2nRNReKQyey-cwJOoEKUhLmN9z/pub'
print_secret_message(doc_url)
