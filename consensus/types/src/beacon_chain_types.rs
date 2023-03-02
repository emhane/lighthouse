pub trait BeaconChainTypes: Send + Sync + 'static {
    type HotStore: store::ItemStore<Self::EthSpec>;
    type ColdStore: store::ItemStore<Self::EthSpec>;
    type SlotClock: slot_clock::SlotClock;
    type Eth1Chain: Eth1ChainBackend<Self::EthSpec>;
    type EthSpec: types::EthSpec;
}