use crate::SandboxArgs;

pub async fn run(args: SandboxArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args {
        SandboxArgs::Build => {
            println!("Building sandbox Docker image...");
            println!("  Image: vest-sandbox:latest");
            println!("  Run manually: docker build -t vest-sandbox:latest .");
        }
        SandboxArgs::Start => {
            println!("Starting sandbox container...");
            println!("  Run manually: docker run -d --name vest-sandbox vest-sandbox:latest");
        }
        SandboxArgs::Clean => {
            println!("Cleaning up sandbox containers...");
            println!("  Run manually: docker rm -f vest-sandbox");
        }
    }
    Ok(())
}
