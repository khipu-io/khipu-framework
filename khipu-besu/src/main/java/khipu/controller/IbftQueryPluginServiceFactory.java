package khipu.controller;

import org.hyperledger.besu.consensus.common.BlockInterface;
import org.hyperledger.besu.consensus.ibft.IbftBlockInterface;
import org.hyperledger.besu.consensus.ibft.queries.IbftQueryServiceImpl;
import org.hyperledger.besu.controller.PluginServiceFactory;
import org.hyperledger.besu.crypto.NodeKey;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.plugin.services.metrics.PoAMetricsService;
import org.hyperledger.besu.plugin.services.query.IbftQueryService;
import org.hyperledger.besu.plugin.services.query.PoaQueryService;
import org.hyperledger.besu.services.BesuPluginContextImpl;

public class IbftQueryPluginServiceFactory implements PluginServiceFactory {

  private final Blockchain blockchain;
  private final NodeKey nodeKey;

  public IbftQueryPluginServiceFactory(final Blockchain blockchain, final NodeKey nodeKey) {
    this.blockchain = blockchain;
    this.nodeKey = nodeKey;
  }

  @Override
  public void appendPluginServices(final BesuPluginContextImpl besuContext) {
    final BlockInterface blockInterface = new IbftBlockInterface();

    final IbftQueryServiceImpl service =
        new IbftQueryServiceImpl(blockInterface, blockchain, nodeKey);
    besuContext.addService(IbftQueryService.class, service);
    besuContext.addService(PoaQueryService.class, service);
    besuContext.addService(PoAMetricsService.class, service);
  }
}
