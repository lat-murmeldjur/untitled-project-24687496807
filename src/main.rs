use alloy::{
    primitives::{address, b256},
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::{BlockNumberOrTag, BlockTransactionsKind, Filter},
    sol,
    sol_types::SolEvent,
};
use eyre::Result;
use futures_util::stream::StreamExt;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ETH10,
    "src/eth10.json"
);

#[tokio::main]
async fn main() -> Result<()> {
    // Set up the WS transport which is consumed by the RPC client.
    // Set up the WS transport which is consumed by the RPC client.
    let rc = "https://core.gashawk.io/rpc";
    let rpc_url = rc.parse()?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    // Create a filter to watch for UNI token transfers.
    let eth10_address = address!("910Cbd523D972eb0a6f4cAe4618aD62622b39DbF");
    let transfer_event_signature =
        b256!("e9e508bad6d4c3227e881ca19068f099da81b5164dd6d62b2eaf1e8bc6c34931");

    let filter = Filter::new()
        .address(eth10_address)
        .event_signature(transfer_event_signature)
        .from_block(19398107);

    let logs = provider.get_logs(&filter).await?;

    println!("logs len: {}", logs.len());

    if true {
        println!("block number: {:?}", logs[0].block_number.unwrap());
        let h = provider.get_block(
            logs[0].block_number.unwrap().into(),
            BlockTransactionsKind::Hashes,
        );
        println!("block {:#?}", h.await);
    } else {
        for log in logs {
            println!("block number: {:?}", log.block_number.unwrap());
            let h = provider.get_block(
                log.block_number.unwrap().into(),
                BlockTransactionsKind::Full,
            );
            println!("block {:#?}", h.await);
        }
    }

    Ok(())
}
