# Dynamicreconpdf.py

from fpdf import FPDF
import os
from datetime import datetime

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Automated Reconnaissance Report', 0, 1, 'C')
        self.set_font('Arial', '', 10)
        self.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_report_from_file(text_report_path, domain):
    """
    Reads a pre-formatted text report and writes its content to a PDF.
    """
    pdf_filename = f"PDF_Report_{domain}.pdf"
    try:
        with open(text_report_path, 'r', encoding='utf-8') as f:
            report_content = f.read()
        pdf = PDF()
        pdf.add_page()
        pdf.set_font("Courier", size=9)
        pdf.multi_cell(0, 5, report_content)
        pdf.output(pdf_filename)
        return (True, os.path.abspath(pdf_filename))
    except FileNotFoundError:
        return (False, f"Error: The report file '{text_report_path}' was not found.")
    except Exception as e:
        return (False, f"An unexpected error occurred during PDF generation: {e}")