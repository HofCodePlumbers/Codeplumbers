import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, useNavigate, Link } from 'react-router-dom';
import Pricing from './Pricing';
import ThreatReport from './ThreatReport';
import Terms from './Terms';
import './App.css';

function HomePage() {
  const [url, setUrl] = useState('');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const normalizeUrl = (inputUrl) => {
    if (!/^https?:\/\//i.test(inputUrl)) {
      return 'http://' + inputUrl;
    }
    return inputUrl;
  };

  // Add sanitizer function for LLM outputs
  const sanitizeLLMOutput = (text) => {
    if (!text) return "";
    
    // Convert to string if not already
    const stringText = String(text);
    
    // Basic HTML/script tag sanitization
    return stringText
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };

  const handleCheck = async (e) => {
    e.preventDefault();
    setLoading(true);

    const trimmedUrl = url.trim();
    const hasUrl = trimmedUrl !== '';
    const hasFile = file !== null;
    let result = null;

    try {
      if (hasUrl) {
        const normalized = normalizeUrl(trimmedUrl);
        const response = await fetch("http://127.0.0.1:5000/api/check_url", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({ url: normalized }).toString(),
        });

        const text = await response.text();
        console.log("Raw response:", text);
        try {
          result = JSON.parse(text);
        } catch (err) {
          console.error("Failed to parse JSON:", err);
          alert("Server response was not valid JSON:\n" + text);
          return;
        }

        if (result.error) {
          alert("Server error: " + result.error);
          return;
        }

        navigate('/threat-report', {
          state: {
            confidence: result.confidence || "N/A",
            report: sanitizeLLMOutput(result.llm_report || result.prediction || result.message || "No report generated."),
            raw: result,
            url: result.url || normalized,
            source: "Manual URL"
          },
        });

      } else if (hasFile) {
        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch("http://127.0.0.1:5000/api/upload_image", {
          method: "POST",
          body: formData,
        });

        const text = await response.text();
        console.log("Raw response:", text);
        try {
          result = JSON.parse(text);
        } catch (err) {
          console.error("Failed to parse JSON:", err);
          alert("Server response was not valid JSON:\n" + text);
          return;
        }

        if (result.error) {
          alert("Server error: " + result.error);
          return;
        }

        navigate('/threat-report', {
          state: {
            confidence: result.confidence || "N/A",
            report: sanitizeLLMOutput(result.llm_report || result.message || "No report generated."),
            raw: result,
            url: result.selected_url || "Unknown",
            source: "Image Upload"
          },
        });

      } else {
        alert("Please enter a valid URL or upload an image.");
        return;
      }
    } catch (error) {
      console.error("Fetch failed:", error);
      alert("There was an error checking the input.");
    } finally {
      setLoading(false);
      setUrl('');
      setFile(null);
    }
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="logo-text">Safe Click</div>
        <Link className="pricing-button" to="/pricing">Pricing</Link>
      </header>

      <main className="main-content">
        <h1 className="main-title">Worried about a sketchy site?</h1>
        <p className="main-subtitle">
          Paste the URL or insert the screenshot below to check if it's safe
        </p>
        <form onSubmit={handleCheck} className="scan-form">
          <input
            className="input-box"
            type="text"
            placeholder="Paste a URL (e.g. google.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <input
            className="file-input"
            type="file"
            accept="image/*"
            onChange={(e) => setFile(e.target.files[0])}
          />
          <br />
          <button className="check-button" type="submit" disabled={loading}>
            {loading ? '⏳ Checking...' : '🔍 Check Safety'}
          </button>
        </form>
        <small style={{ color: '#888' }}>
          Tip: You can enter "example.com" and we'll handle the rest.
        </small>
      </main>

      <footer>
        <div className="footer-content">
          <p>© 2025 SafeClick</p>
          <Link to="/terms"><p>Terms of Service</p></Link>
          <p>Privacy Policy</p>
        </div>
      </footer>
    </div>
  );
}

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/pricing" element={<Pricing />} />
        <Route path="/threat-report" element={<ThreatReport />} />
        <Route path="/terms" element={<Terms />} />
      </Routes>
    </Router>
  );
}

export default App;