# squiggler-v3

Slimmed version of Squiggler that _only_ does the pattern creation within Kibana. See [sample.yaml](sample.yaml) for how to configure. Depending on how many patterns you have, might be a bit memory hungry.

Known to work with 7.x with only data streams or ILM.

## why use this?

If you host a boat load of Elasticsearch clusters that have loads of dynamically named indices coming up all the time, this might be the tool for you. For example, if you have a singular entry point using cross-cluster search to search across multiple clusters, wherein each can have new, uniquely named indices come up using ILM or data streams, instead of making these patterns by hand in your Kibana instance, you can instead run Squiggler.

Every run it'll take inventory of what exists both in Kibana and Elasticsearch using your given origin method, diff the two and create what's missing. No need to manually create tens, hundreds or thousands of patterns.
