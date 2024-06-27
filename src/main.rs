use csv::Writer;
use num::bigint::BigInt;
use std::collections::HashMap;
use std::error::Error;
use std::str::FromStr;
extern crate chrono;
use chrono::Local;

use alloy::{
    primitives::{address, b256, Address},
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::{BlockNumberOrTag, BlockTransactionsKind, Filter},
    sol,
    sol_types::SolEvent,
};

use beacon_api_client::{mainnet::Client, BlockId, StateId};
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

#[derive(Debug, serde::Serialize)]
struct boi {
    block_number: u64,
    hash: String,
    timestamp: u64,
    slot: u64,
    fee_recipient: String,
    fee_received: u128,
    proposer_index: u64,
    tx_from_fee_recipient_txhash: String,
    tx_from_fee_recipient_value: String,
    tx_from_fee_recipient_recipient: String,
    notes: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut blocks_of_interest = vec![];
    // got limited let rc = "https://core.gashawk.io/rpc";
    let rc = "https://eth.drpc.org";

    // let brc = "https://ethereum-beacon-api.publicnode.com";

    let brc = "https://lodestar-mainnet.chainsafe.io";
    // "https://svc.blockdaemon.com/ethereum/mainnet/native/eth/v1/beacon";

    let rpc_url = rc.parse()?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    let url = Url::parse(brc).unwrap();
    let client = Client::new(url);

    let debug = false;

    let address_of_interest = "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF";
    // Create a filter to watch for UNI token transfers.
    let eth10_address = Address::parse_checksummed(address_of_interest, None).unwrap();
    let transfer_event_signature =
        b256!("e9e508bad6d4c3227e881ca19068f099da81b5164dd6d62b2eaf1e8bc6c34931");
    let transfer_event_signature2 =
        b256!("ef519b7eb82aaf6ac376a6df2d793843ebfd593de5f1a0601d3cc6ab49ebb395");

    let filter = Filter::new()
        .address(eth10_address)
        // .event_signature(transfer_event_signature)
        .from_block(15537394); //.to_block(15539394);
                               // .to_block(17034869);

    let logs = provider.get_logs(&filter).await?;

    let ll = logs.len();
    println!("logs len: {}", ll);
    let mut ii = 0;
    for log in logs {
        ii += 1;
        println!("Current {} / {}", ii, ll);

        if debug {
            if ii > 5 {
                break;
            }
        }
        let h = provider
            .get_block_by_number(
                log.block_number.unwrap().into(),
                true, //BlockTransactionsKind::Hashes,
            )
            .await
            .unwrap();

        if debug {
            println!("exbh : {:#?}", h.clone().unwrap().header);

            println!("");
            println!("...");
            println!("");
        }
        let slot1 = 4700013 + (h.clone().unwrap().header.timestamp - 1663224179) / 12;
        let id = BlockId::Slot(slot1);
        let sid = StateId::Slot(slot1);

        if debug {
            println!("slot: {}", id);
        }

        let block = client.get_beacon_block(id).await.unwrap();

        let proposer_index = block.message().proposer_index();

        if debug {
            println!("Proposer index {:#?}", proposer_index);
            println!("state {:#?}", sid);
        }

        if debug {
            let proposer_info = client
                .get_validator(
                    StateId::Head,
                    beacon_api_client::PublicKeyOrIndex::Index(proposer_index),
                )
                .await
                .unwrap();

            println!("Proposer info {:#?}", proposer_info);
        }

        let proposer_hash = "".to_string();

        let e0 = h.clone().unwrap();
        let e1 = e0.header.hash.unwrap();
        let execution_block_hash_as_bytes = format!("{:#?}", e1);

        let f0 = block.message();
        let f1 = f0.body();
        let f2 = f1.execution_payload();
        let f3 = f2.unwrap();
        let mut consensus_payload_hash_as_bytes;

        if debug {
            println!("f3: {:#?}", f3);
        }

        if slot1 < 6209536 {
            let f4 = f3.bellatrix();
            let f5 = &f4.unwrap().block_hash;
            consensus_payload_hash_as_bytes = format!("{:#?}", f5);
        } else if slot1 < 8626176 {
            let f4 = f3.capella();
            let f5 = &f4.unwrap().block_hash;
            consensus_payload_hash_as_bytes = format!("{:#?}", f5);
        } else {
            let f4 = f3.deneb();
            let f5 = &f4.unwrap().block_hash;
            consensus_payload_hash_as_bytes = format!("{:#?}", f5);
        }

        if (consensus_payload_hash_as_bytes != execution_block_hash_as_bytes) {
            panic!("block hash mismatch from beacon query payload and execution query");
        }

        if debug {
            println!("{}", execution_block_hash_as_bytes);
            println!("{}", consensus_payload_hash_as_bytes);
        }

        let b_block_number = h.clone().unwrap().header.number.unwrap();
        let b_hash = consensus_payload_hash_as_bytes;
        let b_timestamp = h.clone().unwrap().header.timestamp;
        let b_slot = block.message().slot();
        let b_fee_recipient = h.clone().unwrap().header.miner.to_string();
        let b_proposer_index = proposer_index as u64;
        let mut b_tx_from_fee_recipient_txhash = "".to_string();
        let mut b_tx_from_fee_recipient_value = "0".to_string();
        let mut b_tx_from_fee_recipient_recipient = "".to_string();
        let mut b_notes = "".to_string();

        let txs0 = h.clone().unwrap();
        let base_fee = txs0.header.base_fee_per_gas.unwrap();
        let txs1 = txs0.transactions.as_transactions().unwrap();
        let mut b_fee_received = 0;

        if debug {
            println!("{:#?}", txs1[0]);
        }

        let txs2 = provider
            .get_block_receipts(BlockNumberOrTag::Number(b_block_number))
            .await
            .unwrap();

        for b in &txs2 {
            for a in b {
                let price = a.effective_gas_price;
                let diff = price - base_fee;
                let multiplied_diff = diff * a.gas_used;
                b_fee_received += multiplied_diff;
            }
        }

        let mut first = true;
        for a in txs1 {
            if a.from.to_string() == b_fee_recipient {
                if first == false {
                    b_notes = "Multiple txs from execution block fee recipient".to_string();
                    let boi = boi {
                        block_number: b_block_number,
                        hash: b_hash.clone(),
                        timestamp: b_timestamp,
                        slot: b_slot,
                        fee_recipient: b_fee_recipient.clone(),
                        fee_received: b_fee_received,
                        proposer_index: b_proposer_index,
                        tx_from_fee_recipient_txhash: b_tx_from_fee_recipient_txhash,
                        tx_from_fee_recipient_value: b_tx_from_fee_recipient_value,
                        tx_from_fee_recipient_recipient: b_tx_from_fee_recipient_recipient,
                        notes: b_notes,
                    };

                    blocks_of_interest.push(boi);

                    println!("multiple txs from fee recipient");
                }

                b_tx_from_fee_recipient_txhash = a.hash.to_string();
                b_tx_from_fee_recipient_value = a.value.to_string();
                b_tx_from_fee_recipient_recipient = a.to.unwrap().to_string();

                println!("{:#?}", a.to.unwrap());

                first = false;
            }
        }

        let boi0 = boi {
            block_number: b_block_number,
            hash: b_hash,
            timestamp: b_timestamp,
            slot: b_slot,
            fee_recipient: b_fee_recipient,
            fee_received: b_fee_received,
            proposer_index: b_proposer_index,
            tx_from_fee_recipient_txhash: b_tx_from_fee_recipient_txhash,
            tx_from_fee_recipient_value: b_tx_from_fee_recipient_value,
            tx_from_fee_recipient_recipient: b_tx_from_fee_recipient_recipient,
        };

        if debug {
            println!("{:#?}", boi0);
        }

        blocks_of_interest.push(boi0);
    }

    let date = Local::now();
    let dtstr = format!(
        "{}-{}.csv",
        date.format("%Y%m%d%H%M%S"),
        address_of_interest
    );

    let mut wtr = Writer::from_path(dtstr)?;

    for a in blocks_of_interest {
        wtr.serialize(a)?;
    }

    // let root = Root::from_hex(root_hex).unwrap();
    // let id = BlockId::Root(root);
    //
    // let block = client.get_beacon_block(id).await.unwrap();
    // dbg!(block);

    Ok(())
}
