# file: quantum_key_sim.py

# from qiskit_ibm_provider import IBMProvider
from qiskit import Aer, QuantumCircuit, execute
import random
import hashlib

# Paste your IBM Quantum token here
IBM_QUANTUM_TOKEN = '1494747394491cab3d6e6c055f8a0745e1f1898098a6ada8ab0fc8e529d7cc1aba1a4c2639eadbc88e0a6ae80c6ca3d7e07f2b37da32ea43d5b194613c35b8dc'

def setup_backend():
    print("[!] Forcing local simulator (offline mode)")
    backend = Aer.get_backend('aer_simulator')
    return backend

def bb84_measure(a_bit, a_basis, b_basis, backend):
    qc = QuantumCircuit(1, 1)
    if a_bit == 1:
        qc.x(0)
    if a_basis == 'X':
        qc.h(0)
    if b_basis == 'X':
        qc.h(0)
    qc.measure(0, 0)
    job = execute(qc, backend=backend, shots=1, memory=True)
    result = job.result().get_memory()[0]
    return int(result)

def generate_bb84_key(bits=128):
    backend = setup_backend()
    alice_bits = [random.randint(0, 1) for _ in range(bits)]
    alice_bases = [random.choice(['Z', 'X']) for _ in range(bits)]
    bob_bases = [random.choice(['Z', 'X']) for _ in range(bits)]
    sifted_key = []
    for i in range(bits):
        if alice_bases[i] == bob_bases[i]:
            result = bb84_measure(alice_bits[i], alice_bases[i], bob_bases[i], backend)
            sifted_key.append(result)
    i = 0
    while len(sifted_key) < 128 and i < bits:
        if alice_bases[i] == bob_bases[i]:
            result = bb84_measure(alice_bits[i], alice_bases[i], bob_bases[i], backend)
            sifted_key.append(result)
        i += 1

# If still not enough, restart loop with new randomness
    while len(sifted_key) < 128:
        extra_bits = generate_bb84_key(bits)
        sifted_key += extra_bits[:128 - len(sifted_key)]

    key_bits = sifted_key[:128]
    key_str = ''.join(map(str, key_bits))
    aes_key = hashlib.sha256(key_str.encode()).digest()[:16]
    return aes_key

if __name__ == "__main__":
    key = generate_bb84_key()
    print("AES Key (hex):", key.hex())

def simulate_bb84(bits=128, tamper_chance=0.2):
    backend = Aer.get_backend('qasm_simulator')

    alice_bits = [random.randint(0, 1) for _ in range(bits)]
    alice_bases = [random.choice(['Z', 'X']) for _ in range(bits)]
    bob_bases = [random.choice(['Z', 'X']) for _ in range(bits)]

    # Simulate Eve tampering
    tampered = []
    for i in range(bits):
        tampered.append(random.random() < tamper_chance)

    sifted_key = []
    errors = 0

    for i in range(bits):
        qc = QuantumCircuit(1, 1)

        if alice_bits[i] == 1:
            qc.x(0)
        if alice_bases[i] == 'X':
            qc.h(0)

        if tampered[i]:  # Eve measures in random basis
            eve_basis = random.choice(['Z', 'X'])
            if eve_basis == 'X':
                qc.h(0)
            qc.measure(0, 0)
            qc = QuantumCircuit(1, 1)  # Reprepare state
            if alice_bits[i] == 1:
                qc.x(0)
            if alice_bases[i] == 'X':
                qc.h(0)

        if bob_bases[i] == 'X':
            qc.h(0)
        qc.measure(0, 0)

        job = execute(qc, backend=backend, shots=1, memory=True)
        bob_bit = int(job.result().get_memory()[0])

        if alice_bases[i] == bob_bases[i]:
            sifted_key.append(bob_bit)
            if bob_bit != alice_bits[i]:
                errors += 1

    error_rate = errors / max(len(sifted_key), 1)

    if error_rate > 0.25:
        print("❌ Eavesdropper detected! Error rate:", round(error_rate, 2))
        return None
    else:
        print("✅ Secure key generated. Error rate:", round(error_rate, 2))

    key_str = ''.join(map(str, sifted_key[:128]))
    return hashlib.sha256(key_str.encode()).digest()[:16]

def safe_generate_key(bits=128):
    for _ in range(3):  # Retry up to 3 times
        key = simulate_bb84(bits=bits)
        if key:
            return key
    raise Exception("❌ Quantum key rejected: eavesdropper detected")

