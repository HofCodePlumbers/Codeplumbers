from qiskit import QuantumCircuit, Aer, execute
from random import randint

def qotp_encrypt_decrypt(message_bits, x_mask, z_mask):
    qc = QuantumCircuit(4, 4)

    # Apply X gates for 1s in message
    for i, bit in enumerate(message_bits):
        if bit == 1:
            qc.x(i)

    # Encrypt with masks
    for i in range(4):
        if x_mask[i]: qc.x(i)
        if z_mask[i]: qc.z(i)

    # Decrypt with same masks
    for i in range(4):
        if z_mask[i]: qc.z(i)
        if x_mask[i]: qc.x(i)

    qc.measure(range(4), range(4))
    backend = Aer.get_backend('qasm_simulator')
    result = execute(qc, backend, shots=1, memory=True).result().get_memory()[0]
    return list(map(int, result[::-1]))  # reverse Qiskit bit order

if __name__ == "__main__":
    message = [randint(0, 1) for _ in range(4)]
    x_mask = [randint(0, 1) for _ in range(4)]
    z_mask = [randint(0, 1) for _ in range(4)]

    print("🔐 Message:", message)
    print("🔑 X Mask :", x_mask)
    print("🔑 Z Mask :", z_mask)

    result = qotp_encrypt_decrypt(message, x_mask, z_mask)
    print("✅ Decrypted:", result)

