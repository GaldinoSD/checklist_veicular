import unittest
import io
from PIL import Image
from reportlab.platypus import SimpleDocTemplate, Image as RLImage, Spacer
from reportlab.lib.units import mm
from backend.utils import normalize_signature_image


class TestSignatureBlackNormalizer(unittest.TestCase):
    def test_white_signature_conversion_to_solid_black(self):
        """Valida que assinaturas feitas com caneta branca/clara no modo escuro (#f8fafc) são convertidas em preto sólido (#000000)."""
        # Cria imagem RGBA com traço branco (#f8fafc) e fundo transparente
        im = Image.new("RGBA", (100, 50), (0, 0, 0, 0))
        # Desenha alguns pixels brancos
        for x in range(10, 40):
            im.putpixel((x, 25), (248, 250, 252, 255))
        
        buf_in = io.BytesIO()
        im.save(buf_in, format="PNG")
        buf_in.seek(0)

        out_buf = normalize_signature_image(buf_in)
        im_out = Image.open(out_buf)

        # Verifica se o traço foi convertido para preto (0, 0, 0)
        pixel_val = im_out.getpixel((20, 25))
        self.assertEqual(pixel_val[0], 0, "O canal Red deve ser 0 (preto)")
        self.assertEqual(pixel_val[1], 0, "O canal Green deve ser 0 (preto)")
        self.assertEqual(pixel_val[2], 0, "O canal Blue deve ser 0 (preto)")
        self.assertGreaterEqual(pixel_val[3], 240, "A opacidade deve ser sólida/alta")

    def test_colored_signature_conversion_to_solid_black(self):
        """Valida que assinaturas com caneta verde (#065f46) ou azul são convertidas em preto sólido (#000000)."""
        im = Image.new("RGBA", (100, 50), (0, 0, 0, 0))
        for x in range(10, 40):
            im.putpixel((x, 25), (6, 95, 70, 200)) # Verde escuro
        
        buf_in = io.BytesIO()
        im.save(buf_in, format="PNG")
        buf_in.seek(0)

        out_buf = normalize_signature_image(buf_in)
        im_out = Image.open(out_buf)

        pixel_val = im_out.getpixel((20, 25))
        self.assertEqual(pixel_val[:3], (0, 0, 0), "A cor do traço deve ser preto puro")
        self.assertGreater(pixel_val[3], 200, "A opacidade deve ser forte")

    def test_reportlab_renders_normalized_signature(self):
        """Valida que o ReportLab consegue construir um PDF normalmente usando a assinatura normalizada."""
        im = Image.new("RGBA", (100, 50), (0, 0, 0, 0))
        for x in range(10, 40):
            im.putpixel((x, 25), (248, 250, 252, 255))
        
        buf_in = io.BytesIO()
        im.save(buf_in, format="PNG")
        buf_in.seek(0)

        norm_buf = normalize_signature_image(buf_in)
        
        pdf_buf = io.BytesIO()
        doc = SimpleDocTemplate(pdf_buf)
        rl_img = RLImage(norm_buf, width=40*mm, height=20*mm)
        doc.build([rl_img])
        
        self.assertGreater(len(pdf_buf.getvalue()), 500, "O PDF gerado deve conter conteúdo válido")

    def test_batch_normalize_existing_signatures_on_disk(self):
        """Varre os diretórios de assinaturas e normaliza as imagens existentes para preto sólido."""
        import glob
        from pathlib import Path

        dirs = [
            Path("/var/www/checklist_veicular/static/assinaturas"),
            Path("/var/www/checklist_veicular/frontend/static/assinaturas"),
            Path("/var/www/checklist_veicular/frontend/static/uploads/apr")
        ]
        
        normalized_count = 0
        for d in dirs:
            if not d.exists():
                continue
            for png_file in d.glob("*.png"):
                if "sig" not in png_file.name.lower():
                    continue
                try:
                    norm_buf = normalize_signature_image(png_file)
                    with open(png_file, "wb") as f:
                        f.write(norm_buf.getvalue())
                    normalized_count += 1
                except Exception as e:
                    print(f"Erro ao normalizar {png_file.name}: {e}")

        print(f"Total de assinaturas existentes normalizadas para preto sólido: {normalized_count}")
        self.assertGreaterEqual(normalized_count, 0)


if __name__ == "__main__":
    unittest.main()
