#include <stdio.h>
#include <stdlib.h>
#include <hpdf.h>

#define PAGE_WIDTH 595
#define PAGE_HEIGHT 842
#define MARGIN 50
#define LINE_HEIGHT 20
#define FONT_SIZE 12
#define CELL_PADDING 5

void drawText(HPDF_Page page, HPDF_REAL x, HPDF_REAL y, const char *text) {
    HPDF_Page_BeginText(page);
    HPDF_Page_MoveTextPos(page, x, y);
    HPDF_Page_ShowText(page, text);
    HPDF_Page_EndText(page);
}

void drawCell(HPDF_Page page, HPDF_REAL x, HPDF_REAL y, HPDF_REAL width, HPDF_REAL height, const char *text) {
    HPDF_Page_Rectangle(page, x, y - height, width, height);
    HPDF_Page_Stroke(page);

    drawText(page, x + CELL_PADDING, y - CELL_PADDING - (height / 2), text);
}

int main() {
    HPDF_Doc pdf;
    HPDF_Page page;
    const char *pdf_file = "invoice_with_borders.pdf";

    // Creazione di un nuovo documento PDF
    pdf = HPDF_New(NULL, NULL);
    if (!pdf) {
        printf("Error: cannot create PdfDoc object\n");
        return 1;
    }

    // Aggiunta di una nuova pagina al PDF
    page = HPDF_AddPage(pdf);
    if (!page) {
        printf("Error: cannot add new page\n");
        HPDF_Free(pdf);
        return 1;
    }

    // Impostazioni pagina
    HPDF_Page_SetSize(page, HPDF_PAGE_SIZE_A4, HPDF_PAGE_PORTRAIT);
    HPDF_Page_SetWidth(page, PAGE_WIDTH);
    HPDF_Page_SetHeight(page, PAGE_HEIGHT);

    // Impostazione del tipo di carattere e delle dimensioni
    HPDF_Font font = HPDF_GetFont(pdf, "Helvetica", NULL);
    if (!font) {
        printf("Error: cannot get font\n");
        HPDF_Free(pdf);
        return 1;
    }
    HPDF_Page_SetFontAndSize(page, font, FONT_SIZE);

    // Disegno delle informazioni della fattura
    HPDF_REAL y = PAGE_HEIGHT - MARGIN;

    drawText(page, MARGIN, y, "Nome Cliente: ABC Company");
    y -= LINE_HEIGHT;
    drawText(page, MARGIN, y, "Indirizzo: Via delle Rose, 123");
    y -= LINE_HEIGHT;
    drawText(page, MARGIN, y, "Città: Città Principale");
    y -= LINE_HEIGHT * 2;

    // Intestazione della tabella
    drawCell(page, MARGIN, y, 200, LINE_HEIGHT, "Prodotto");
    drawCell(page, MARGIN + 200, y, 100, LINE_HEIGHT, "Quantità");
    drawCell(page, MARGIN + 300, y, 100, LINE_HEIGHT, "Prezzo unitario");
    drawCell(page, MARGIN + 400, y, 100, LINE_HEIGHT, "Totale");
    y -= LINE_HEIGHT;

    // Dettagli degli articoli
    drawCell(page, MARGIN, y, 200, LINE_HEIGHT, "Prodotto A");
    drawCell(page, MARGIN + 200, y, 100, LINE_HEIGHT, "2");
    drawCell(page, MARGIN + 300, y, 100, LINE_HEIGHT, "$50");
    drawCell(page, MARGIN + 400, y, 100, LINE_HEIGHT, "$100");
    y -= LINE_HEIGHT;

    drawCell(page, MARGIN, y, 200, LINE_HEIGHT, "Prodotto B");
    drawCell(page, MARGIN + 200, y, 100, LINE_HEIGHT, "1");
    drawCell(page, MARGIN + 300, y, 100, LINE_HEIGHT, "$80");
    drawCell(page, MARGIN + 400, y, 100, LINE_HEIGHT, "$80");
    y -= LINE_HEIGHT * 2;

    // Totale
    drawText(page, MARGIN + 300, y, "Totale:");
    drawText(page, MARGIN + 400, y, "$180");

    // Salvataggio del PDF in un file
    HPDF_SaveToFile(pdf, pdf_file);

    // Libera la memoria allocata
    HPDF_Free(pdf);

    printf("PDF file created: %s\n", pdf_file);

    return 0;
}
