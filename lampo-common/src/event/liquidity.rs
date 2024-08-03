use bitcoin::secp256k1::PublicKey;
use lightning_liquidity::{lsps0::ser::RequestId, lsps2::msgs::OpeningFeeParams};

#[derive(Debug, Clone)]
pub enum LiquidityEvent {
    OpenParamsReady {
        counterparty_node_id: PublicKey,
        opening_fee_params_menu: Vec<OpeningFeeParams>,
    },
    InvoiceparamsReady {
        counterparty_node_id: PublicKey,
        intercept_scid: u64,
        cltv_expiry_delta: u32,
    },
    BuyRequest {
        request_id: RequestId,
        counterparty_node_id: PublicKey,
        opening_fee_params: OpeningFeeParams,
        payment_size_msat: Option<u64>,
    },
    Geinfo {
        request_id: RequestId,
        counterparty_node_id: PublicKey,
        token: Option<String>,
    },
    OpenChannel {
        their_network_key: PublicKey,
        amt_to_forward_msat: u64,
        opening_fee_msat: u64,
        user_channel_id: u128,
        intercept_scid: u64,
    },
}
