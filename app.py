import re
import asyncio
import hashlib
import json
from typing import Optional, List
from pydantic import BaseModel, validator, Field
import aiohttp
import pandas as pd
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PyPDF2 import PdfReader
from datetime import datetime, timedelta
import streamlit as st
from groq import Groq
import os
from dotenv import load_dotenv
from io import BytesIO
from fpdf import FPDF

# --- Load environment variables ---
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=GROQ_API_KEY)

# --- AES Encryption Utility ---
class Encryptor:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, data: str) -> str:
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return json.dumps({"nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()})

# --- Data Models ---
class PersonalInfo(BaseModel):
    cnic: str
    ntn: str
    mobile_number: str
    iban: str

    @validator('cnic')
    def validate_cnic(cls, v):
        assert re.match(r'^\d{13}$', v), "Invalid CNIC format"
        return v

    @validator('ntn')
    def validate_ntn(cls, v):
        assert re.match(r'^(\d{7}|\d{12})$', v), "Invalid NTN format"
        return v

    @validator('mobile_number')
    def validate_mobile(cls, v):
        assert re.match(r'^\+92\d{10}$', v), "Invalid mobile number"
        return v

    @validator('iban')
    def validate_iban(cls, v):
        assert re.match(r'^PK\d{2}[A-Z0-9]{16,30}$', v), "Invalid IBAN"
        return v

class ValidationErrorDetail(BaseModel):
    code: str
    message: str
    suggestion: Optional[str] = None

class ValidationResult(BaseModel):
    field: str
    value: Optional[float]
    is_valid: bool
    warnings: List[str] = []
    errors: List[ValidationErrorDetail] = []

# --- PDF Report Generator ---
def generate_pdf_report(df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Pakistan Tax Filing Validation Report", ln=True, align='C')
    pdf.ln(10)

    for i, row in df.iterrows():
        pdf.cell(200, 10, txt=f"Row {i+1}: Valid = {row['Valid']}", ln=True)
        pdf.multi_cell(0, 10, txt=f"Errors: {row['Errors'] if row['Errors'] else 'None'}")
        pdf.ln(2)

    pdf_output = BytesIO()
    pdf.output(pdf_output)
    return pdf_output.getvalue()

# --- Streamlit UI ---
st.set_page_config(page_title="🇵🇰 Pakistan Tax Filing Assistant", layout="centered")
st.title("📄 Pakistan Tax Filing Assistant")

uploaded_file = st.file_uploader("📤 Upload Edited Excel/CSV for Re-validation", type=["csv", "xlsx"])
if uploaded_file:
    try:
        if uploaded_file.name.endswith(".csv"):
            df_uploaded = pd.read_csv(uploaded_file)
        else:
            df_uploaded = pd.read_excel(uploaded_file)

        summary_data = []

        for index, row in df_uploaded.iterrows():
            try:
                info = PersonalInfo(
                    cnic=str(row['CNIC']),
                    ntn=str(row['NTN']),
                    mobile_number=str(row['Mobile']),
                    iban=str(row['IBAN'])
                )
                result = validate_income_report(
                    declared_income=row['Declared Income'],
                    bank_turnover=row['Bank Turnover'],
                    declared_tax=row['Declared Tax'],
                    fbr_tax=row['FBR Tax']
                )
                log_audit(result.dict())
                summary_data.append({
                    "CNIC": row['CNIC'],
                    "NTN": row['NTN'],
                    "Valid": result.is_valid,
                    "Errors": "; ".join([e.message for e in result.errors])
                })
            except Exception as e:
                summary_data.append({
                    "CNIC": row.get('CNIC', 'Unknown'),
                    "NTN": row.get('NTN', 'Unknown'),
                    "Valid": False,
                    "Errors": str(e)
                })

        summary_df = pd.DataFrame(summary_data)
        st.subheader("📊 Summary Table")
        st.dataframe(summary_df)

        error_rows = summary_df[~summary_df['Valid']]
        if not error_rows.empty:
            st.download_button("Download Only Error Rows (CSV)", error_rows.to_csv(index=False).encode(), "error_rows.csv", "text/csv")

        st.download_button("📄 Download PDF Report", generate_pdf_report(summary_df), file_name="validation_report.pdf", mime="application/pdf")

    except Exception as e:
        st.error(f"Failed to process uploaded file: {str(e)}")
