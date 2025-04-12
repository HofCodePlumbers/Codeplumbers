import streamlit as st
from qiskit import QuantumCircuit
import matplotlib.pyplot as plt
from quantum_key_sim import simulate_bb84

st.title("🔐 BB84 Quantum Key Exchange Viewer")

st.markdown("Simulates quantum key generation with optional eavesdropper tampering.")

tamper = st.slider("Eavesdropper Probability", 0.0, 1.0, 0.2, 0.05)
key = simulate_bb84(bits=16, tamper_chance=tamper)

if key is None:
    st.error("❌ Key rejected — Eve detected!")
else:
    st.success("✅ Secure key accepted")
    st.code(key.hex(), language="plaintext")

# Generate visual circuit
qc = QuantumCircuit(1, 1)
qc.h(0)
qc.measure(0, 0)
st.pyplot(qc.draw(output="mpl"))

