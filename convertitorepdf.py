import fitz  # PyMuPDF
from pdf2image import convert_from_path
import os

def pdf_to_html_custom(pdf_path, output_dir):
    # Crea cartelle di output
    images_dir = os.path.join(output_dir, "images")
    os.makedirs(images_dir, exist_ok=True)

    # Estrarre immagini dal PDF
    pages = convert_from_path(pdf_path, dpi=300)
    image_paths = []
    for i, page in enumerate(pages):
        image_path = os.path.join(images_dir, f"page_{i + 1}.png")
        page.save(image_path, "PNG")
        image_paths.append(image_path)

    # Estrarre testo e creare HTML
    doc = fitz.open(pdf_path)
    html_content = "<html><body>"
    for i, page in enumerate(doc):
        html_content += f"<h2>Pagina {i + 1}</h2>"
        html_content += f"<img src='{image_paths[i]}' width='100%'><br>"
        text = page.get_text("text")
        html_content += f"<pre>{text}</pre><hr>"

    html_content += "</body></html>"

    # Salva il file HTML
    html_output = os.path.join(output_dir, "output.html")
    with open(html_output, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"Conversione completata! HTML salvato in {html_output}")

# Esempio di utilizzo
pdf_to_html_custom("file.pdf", "output_directory")
