import json
import hashlib
import time

class BlockchainMiner:
    def __init__(self):
        self.chain = []
        self.pending_messages = []
        self.pending_users = []
        self.load_data()

    def load_data(self):
        try:
            with open("blockchain1.json", "r") as f:
                data = json.load(f)
                self.chain = data.get("chain", [])
                self.pending_messages = data.get("pending_messages", [])
                self.pending_users = data.get("pending_users", [])
        except (FileNotFoundError, json.JSONDecodeError):
            self.chain = []
            self.pending_messages = []
            self.pending_users = []

    def save_data(self):
        with open("blockchain1.json", "w") as f:
            json.dump(
                {"chain": self.chain, "pending_messages": self.pending_messages, "pending_users": self.pending_users},
                f,
                indent=4,
            )

    def proof_of_work(self, previous_proof):
        """ Simple proof of work for mining """
        new_proof = 1
        while True:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == "0000":
                return new_proof
            new_proof += 1

    def mine_block(self):
        """ Mines a block containing pending users and messages """
        if not self.pending_messages and not self.pending_users:
            print("No transactions or users to mine!")
            return

        previous_block = self.chain[-1] if self.chain else None
        previous_proof = previous_block["proof"] if previous_block else 1
        previous_hash = hashlib.sha256(json.dumps(previous_block, sort_keys=True).encode()).hexdigest() if previous_block else "0"

        proof = self.proof_of_work(previous_proof)

        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "users": self.pending_users,
            "messages": self.pending_messages,
            "proof": proof,
            "previous_hash": previous_hash,
        }

        self.chain.append(block)
        self.pending_messages = []  # Clear pending messages after mining
        self.pending_users = []  # Clear pending users after mining
        self.save_data()
        print(f"Block {block['index']} mined successfully with {len(block['users'])} users and {len(block['messages'])} messages!")

if __name__ == "__main__":
    miner = BlockchainMiner()

    print("Mining new users and messages...")
    miner.mine_block()
