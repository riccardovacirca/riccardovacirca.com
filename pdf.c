#include <stdio.h>
#include <stdlib.h>
#include <hpdf.h>

int main() {
    HPDF_Doc pdf;
    HPDF_Page page;
    const char *pdf_file = "hello.pdf";

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

    // Impostazione del tipo di carattere e delle dimensioni
    HPDF_Font font = HPDF_GetFont(pdf, "Helvetica", NULL);
    if (!font) {
        printf("Error: cannot get font\n");
        HPDF_Free(pdf);
        return 1;
    }
    HPDF_Page_SetFontAndSize(page, font, 24);

    // Testo nella pagina
    HPDF_Page_BeginText(page);
    HPDF_Page_MoveTextPos(page, 50, 400);
    HPDF_Page_ShowText(page, "Hello, PDF using libHaru!");
    HPDF_Page_EndText(page);

    // Aggiunta del campo AcroForm
    HPDF_Destination dst = HPDF_Page_CreateDestination(page);
    HPDF_Rect rect = {50, 300, 200, 330}; // Posizione e dimensioni del campo
    HPDF_CreateTextField(pdf, "myTextField", "This is a text field", font, 12, rect);
    HPDF_SetDestination(page, dst);

    /* Save the PDF to a file */
    HPDF_SaveToFile(pdf, pdf_file);

    /* Clean up */
    HPDF_Free(pdf);

    printf("PDF file created: %s\n", pdf_file);

    return 0;
}
