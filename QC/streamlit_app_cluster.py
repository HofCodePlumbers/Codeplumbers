#file: streamlit_clustering.py
import requests
import streamlit as st

st.set_page_config(page_title="🧩 Quantum Clustering", page_icon="$st.title(🧩 Quantum Clustering (Local Simulator)")

st.markdown("""
Welcome to the Quantum Clustering Interface.

💻 Backend: Flask API with Quantum Circuit (Local Simulator)
🚀 No IBM Cloud, No IBM Provider required
""")

#Input: user data points
input_data = st.text_area(
    "Enter data points (comma-separated, rows as semicolon):",
    "1,2,3;4,5,6;7,8,9"
)

if st.button("Run Quantum Clustering"):
    try:
        points = [
            [float(x) for x in row.split(",")]
            for row in input_data.strip().split(";")
        ]
        response = requests.post("http://127.0.0.1:5000/quantum_cl$", json={"data": points})
        result = response.json()

        st.success(f"Cluster Labels: {result['labels']}")
        st.json(result)

    except Exception as e:
      st.error(f"Error: {e}")