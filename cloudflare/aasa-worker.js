import { petAssets } from "./pet-assets.js";

const appleAppSiteAssociation = {
  applinks: {
    apps: [],
    details: [
      {
        appIDs: ["TEAMID.com.example.codexrayban"],
        components: [
          {
            "/": "/oauth/callback",
            comment: "Codex OAuth callback",
          },
          {
            "/": "/auth/*",
            comment: "Future auth routes",
          },
        ],
      },
    ],
  },
};

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/.well-known/apple-app-site-association") {
      return Response.json(appleAppSiteAssociation, {
        headers: {
          "Cache-Control": "public, max-age=300",
        },
      });
    }

    if (url.pathname.startsWith("/codex-pets/")) {
      const fileName = url.pathname.split("/").pop() || "";
      const encoded = petAssets[fileName];
      if (!encoded) {
        return new Response("Not found", { status: 404 });
      }

      const body = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
      return new Response(body, {
        headers: {
          "Cache-Control": "public, max-age=31536000, immutable",
          "Content-Type": "image/gif",
        },
      });
    }

    return new Response("Not found", {
      status: 404,
      headers: {
        "Cache-Control": "public, max-age=60",
      },
    });
  },
};
