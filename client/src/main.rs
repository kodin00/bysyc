use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_title("bysyc"),
        ..Default::default()
    };
    eframe::run_native(
        "bysyc",
        options,
        Box::new(|_cc| Ok(Box::new(BysycApp::default()))),
    )
}

/// Root application state. Milestone 1 (auth) replaces this placeholder.
#[derive(Default)]
struct BysycApp;

impl eframe::App for BysycApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("bysyc");
            ui.label("scaffold — auth comes with milestone 1");
        });
    }
}
