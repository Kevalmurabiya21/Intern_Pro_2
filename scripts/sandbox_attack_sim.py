"""
Safe, self-contained test trigger for RDRS.

This is NOT malware and NOT a dataset. It only ever touches files inside
data/sandbox: it creates throwaway text files, then overwrites them with
random bytes (so they look encrypted) and renames them with a .locked
extension - the same idea as the harmless EICAR test file used to check
antivirus software. It never touches anything outside the sandbox folder,
never spreads, and deletes nothing of yours.

Run the monitor first (python -m app.main), then run this script in a
second terminal to trigger a detection.
"""
import os
import pathlib

SANDBOX = pathlib.Path("data/sandbox")


def run():
    SANDBOX.mkdir(parents=True, exist_ok=True)

    print(f"[1/2] Creating 50 normal files in {SANDBOX}/ ...")
    for i in range(50):
        (SANDBOX / f"file_{i}.txt").write_text("normal document content")

    print("[2/2] Simulating an attack: overwrite with random bytes + rename to .locked ...")
    for f in list(SANDBOX.glob("*.txt")):
        f.write_bytes(os.urandom(20000))          # high-entropy, looks encrypted
        # `replace` overwrites only a prior simulated .locked file in this
        # dedicated sandbox, making the safe demo repeatable on Windows.
        f.replace(f.with_suffix(".locked"))        # mass extension change

    print("Done. Check the monitor output / dashboard / logs/alerts.log for a Critical detection.")


if __name__ == "__main__":
    run()
