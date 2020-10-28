from project import db
from project.models import Challenge

def add_challenges():
    sha = sha256(b"flag").hexdigest()
    test_challenge = Challenge(title="Test2", description="Some testing stuff", points=10, flag_hash=sha, category="misc")
    db.session.add(test_challenge)

    sha = sha256(b"flag1").hexdigest()
    test_challenge_1 = Challenge(title="Test1", description="Some more testing stuff", points=10, flag_hash=sha, category="misc")
    db.session.add(test_challenge_1)
    db.session.commit()
