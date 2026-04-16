use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match rscale::cli::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
