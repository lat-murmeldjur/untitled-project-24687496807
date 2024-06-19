use alloy::{
    primitives::{address, b256},
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::{BlockNumberOrTag, BlockTransactionsKind, Filter},
    sol,
    sol_types::SolEvent,
};

use beacon_api_client::{mainnet::Client, BlockId};
use ethereum_consensus::primitives::Root;
use hex::FromHex;
use url::Url;

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
    let brc = "https://ethereum-beacon-api.publicnode.com";
    // let brc = "https://lb.drpc.org/rest/eth-beacon-chain";
    let rpc_url = rc.parse()?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    let url = Url::parse(brc).unwrap();
    let client = Client::new(url);

    // Create a filter to watch for UNI token transfers.
    let eth10_address = address!("910Cbd523D972eb0a6f4cAe4618aD62622b39DbF");
    let transfer_event_signature =
        b256!("e9e508bad6d4c3227e881ca19068f099da81b5164dd6d62b2eaf1e8bc6c34931");
    let transfer_event_signature2 =
        b256!("ef519b7eb82aaf6ac376a6df2d793843ebfd593de5f1a0601d3cc6ab49ebb395");

    let filter = Filter::new()
        //.address(eth10_address)
        .event_signature(transfer_event_signature2)
        .from_block(20126208);

    let logs = provider.get_logs(&filter).await?;

    println!("logs len: {}", logs.len());

    if true {
        println!("block number: {:?}", logs[0].block_number.unwrap());
        let h = provider
            .get_block_by_number(
                logs[0].block_number.unwrap().into(),
                false, //BlockTransactionsKind::Hashes,
            )
            .await
            .unwrap();

        println!("block {:#?}", h);

        println!("");
        println!("");
        println!("...");
        println!("");
        println!("");

        println!("root {:#?}", h.clone().unwrap().header.state_root);

        let str1: String =
            (&h.clone().unwrap().header.parent_beacon_block_root.unwrap()).to_string();

        let root = Root::from_hex(str1).unwrap();
        let id = BlockId::Root(root);

        println!("root {:#?}", root);
        println!("id {:#?}", id);

        let block = client.get_beacon_block(id).await.unwrap();
        println!("{:#?}", block.message().body().attestations());
    } else {
        for log in logs {
            println!("block number: {:?}", log.block_number.unwrap());
            let h = provider.get_block_by_number(
                log.block_number.unwrap().into(),
                false, // BlockTransactionsKind::Full,
            );
            println!("block {:#?}", h.await);
        }
    }

    // let root = Root::from_hex(root_hex).unwrap();
    // let id = BlockId::Root(root);
    //
    // let block = client.get_beacon_block(id).await.unwrap();
    // dbg!(block);

    Ok(())
}
