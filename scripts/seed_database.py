"""Script entrypoint to seed MongoDB database with initial devices and profiles."""

from database.seed_database import seed_database

if __name__ == "__main__":
    result = seed_database()
    print("Database seeding result:", result)
