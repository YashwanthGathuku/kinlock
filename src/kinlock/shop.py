"""The simulated shop behind the demo. No real purchase or transfer is ever made.

Usual baskets are what the owner saved. Catalog entries let the simulated
Alexa+ turn "order the laptop from TechZone" into a structured request, the way
Alexa+ itself would fill the tool's arguments.
"""

from __future__ import annotations

# list name -> (merchant, amount in cents, category, spoken label)
USUAL: dict[str, tuple[str, int, str, str]] = {
    "groceries": ("Fresh Market", 4620, "groceries", "your usual groceries"),
    "pharmacy": ("Corner Pharmacy", 1840, "pharmacy", "your prescription refill"),
}

# keyword -> (merchant, amount in cents, category, item)
CATALOG: dict[str, tuple[str, int, str, str]] = {
    "laptop": ("TechZone", 84999, "electronics", "a laptop"),
    "gift card": ("Gift Card Outlet", 50000, "gift cards", "gift cards"),
    "prescription": ("Corner Pharmacy", 1840, "pharmacy", "your prescription refill"),
    "book": ("Book Nook", 2499, "books", "a book"),
}
