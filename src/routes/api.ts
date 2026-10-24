import { Router } from "express";
import type { Dependencies } from "../dependencies.ts";
import { getCurrentSession } from "../auth/sessions.ts";
import {
  findOrderById,
  listAllOrders,
  listOrderItems,
  listOrdersForUser,
  type Order,
  type OrderItem,
} from "../orders/index.ts";
import { listProducts, type Product } from "../products.ts";
import { findApiKey } from "../auth/apiKeys.ts";
import { createRateLimiter } from "../security/rateLimit.ts";
// import { it } from "node:test";

type ProductResponse = {
  id: number;
  name: string;
  description: string;
  image_path: string;
  price_cents: number;
};

type OrderResponse = {
  id: number;
  status: Order["status"];
  total_cents: number;
  created_at: string;
};

type OrderItemResponse = {
  product_id: number;
  product_name: string;
  quantity: number;
  price_cents: number;
};

function toProductResponse(product: Product): ProductResponse {
  return {
    id: product.id,
    name: product.name,
    description: product.description,
    image_path: product.image_path,
    price_cents: product.price_cents,
  };
}

function toOrderResponse(order: Order): OrderResponse {
  return {
    id: order.id,
    status: order.status,
    total_cents: order.total_cents,
    created_at: order.created_at,
  };
}

function toOrderItemResponse(item: OrderItem): OrderItemResponse {
  return {
    product_id: item.product_id,
    product_name: item.product_name,
    quantity: item.quantity,
    price_cents: item.price_cents,
  };
}


export function createApiRouter(deps: Dependencies): Router {
  const { db } = deps;
  const router = Router();

  const productRateLimiter = createRateLimiter({
    windowSeconds: 60,
    max: 30,
  });

  router.get("/api/account/orders", (req, res) => {
    const current = getCurrentSession(db, req.header("cookie"));
    if (!current) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    const orders = listOrdersForUser(db, current.user.id).map(toOrderResponse);
    res.json({ orders });
  });

  router.get("/api/orders/:id", (req, res) => {
    const current = getCurrentSession(db, req.header("cookie"));
    if (!current) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    const orderId = Number(req.params.id);
    if (!Number.isSafeInteger(orderId) || current.user.id !== orderId) {
      res.status(404).json({ error: "Order not found" });
      return;
    }

    const order = findOrderById(db, orderId);
    if (!order || order.user_id !== current.user.id) {
      res.status(404).json({ error: "Order not found" });
      return;
    }

    const items = listOrderItems(db, order.id).map(toOrderItemResponse);
    res.json({ order: toOrderResponse(order), items });
  });

  router.get("/api/products", productRateLimiter, (_req, res) => {
    const products = listProducts(db).map(toProductResponse);
    res.json({ products });
  });

  router.get("/api/integrations/warehouse/orders", (_req, res) => {
    const apiKeyHeader = _req.header("x-api-key") ?? "";
    const apiKey = findApiKey(db, apiKeyHeader);
    if (!apiKey) {
      res.status(401).json({ error: "Invalid API key" });
      return;
    }
    if (apiKey.scope !== "orders:read") {
      res.status(403).json({ error: "API key scope is not allowed" });
      return;
    }

    const orders = listAllOrders(db).map((order) => ({
      id: order.id,
      status: order.status,
      total_cents: order.total_cents,
      created_at: order.created_at,
    }));

    res.json({
      integration: "Warehouse Fulfillment Integration",
      orders,
    });
  });

  return router;
}
