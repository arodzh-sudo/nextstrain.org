/* eslint no-use-before-define: ["error", {"functions": false, "classes": false}] */
const authz = require("../authz");
const {Source, Dataset, DatasetSubresource, Narrative, NarrativeSubresource} = require("./models");

class UrlDefinedSource extends Source {
  static get _name() { return "fetch"; }

  constructor(authority) {
    super();

    if (!authority) throw new Error(`Cannot construct a ${this.constructor.name} without a URL authority`);

    this.authority = authority;
  }

  async baseUrl() {
    return `https://${this.authority}`;
  }
  dataset(pathParts) {
    return new UrlDefinedDataset(this, pathParts);
  }
  narrative(pathParts) {
    return new UrlDefinedNarrative(this, pathParts);
  }

  // available datasets & narratives are unknown when the dataset is specified by the URL
  async availableDatasets() { return []; }
  async availableNarratives() { return []; }
  async getInfo() { return {}; }

  get authzPolicy() {
    return [
      {tag: authz.tags.Visibility.Public, role: "*", allow: [authz.actions.Read]},
    ];
  }
  get authzTags() {
    return new Set([
      authz.tags.Type.Source,
      authz.tags.Visibility.Public,
    ]);
  }
  get authzTagsToPropagate() {
    return new Set([
      authz.tags.Visibility.Public,
    ]);
  }
}

class UrlDefinedDataset extends Dataset {
  get baseName() {
    return this.baseParts.join("/");
  }
  subresource(type) {
    return new UrlDefinedDatasetSubresource(this, type);
  }
}

class UrlDefinedDatasetSubresource extends DatasetSubresource {
  get baseName() {
    const type = this.type;
    const baseName = this.resource.baseName;

    if (type === "main") {
      return baseName;
    }

    return baseName.endsWith(".json")
      ? `${baseName.replace(/\.json$/, '')}_${type}.json`
      : `${baseName}_${type}`;
  }
}

class UrlDefinedNarrative extends Narrative {
  get baseName() {
    return this.baseParts.join("/");
  }
  subresource(type) {
    return new UrlDefinedNarrativeSubresource(this, type);
  }
}

class UrlDefinedNarrativeSubresource extends NarrativeSubresource {
  get baseName() {
    return this.resource.baseName;
  }
}

module.exports = {
  UrlDefinedSource,
};
